// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package autocertdelegate provides a mechanism to provision LetsEncrypt certs
// for internal LAN TLS servers (that aren't reachable publicly) via a delegated
// server that is.
//
// See also https://github.com/bradfitz/autocertdelegate.
package autocertdelegate

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Server is an http.Handler that runs on the Internet-facing daemon
// and gets the TLS certs from LetsEncrypt (using ALPN challenges) and
// gives them out to internal clients.
//
// It will only give them out to internal clients whose DNS names
// resolve to internal IP addresses and who can provide that they are
// running code on that IP address. (This assumes that such hostnames
// aren't multi-user systems with untrusted users.)
type Server struct {
	am  *autocert.Manager
	key []byte
}

// NewServer returns a new server given an autocert.Manager
// configuration.
func NewServer(am *autocert.Manager) *Server {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &Server{
		am:  am,
		key: key,
	}
}

// validDelegateServerName reports whether n is a valid name that we
// can be a delegate cert fetcher for. It must be a bare DNS name (no
// port, not an IP address).
func validDelegateServerName(n string) bool {
	if n == "" {
		return false
	}
	if !strings.Contains(n, ".") {
		return false
	}
	if strings.Contains(n, ":") {
		// Contains port or is IPv6 literal.
		return false
	}
	if net.ParseIP(n) != nil {
		// No IPs.
		return false
	}
	if "x://"+n != (&url.URL{Scheme: "x", Host: n}).String() {
		// name must have contained invalid characters and caused escaping.
		return false
	}
	return true
}

// validChallengeAddr reports whether a is a valid IP address to serve
// a delegated cert to.
func validChallengeAddr(a string) bool {
	// TODO: flesh this out. parse a, make configurable, support
	// IPv6. Good enough for now.
	return strings.HasPrefix(a, "10.") || strings.HasPrefix(a, "192.168.")
}

// badServerName says that something's wrong with the servername
// parameter, without saying what, as this might be hit by the outside world.
func badServerName(w http.ResponseWriter) {
	http.Error(w, "missing or invalid servername", 403) // intentionally vague
}

func challengeAnswer(masterKey []byte, serverName string, t time.Time) string {
	hm := hmac.New(sha256.New, masterKey)
	fmt.Fprintf(hm, "%s-%d", serverName, t.Unix())
	return fmt.Sprintf("%x", hm.Sum(nil))
}

// ServeHTTP is the HTTP handler to get challenges & certs for the Client.
// The Handler only responds to GET requests over TLS. It can be installed
// at any path, but the client only makes requests to the root. It's assumed
// that any existing HTTP mux is routing based on the hostname.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "TLS required", 403)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "wrong method; want GET", 400)
		return
	}
	serverName := r.FormValue("servername")
	if !validDelegateServerName(serverName) {
		log.Printf("autocertdelegate: invalid server name %q", serverName)
		badServerName(w)
		return
	}
	if err := s.am.HostPolicy(r.Context(), serverName); err != nil {
		log.Printf("autocertdelegate: %q denied by configured HostPolicy: %v", serverName, err)
		badServerName(w)
		return
	}

	switch r.FormValue("mode") {
	default:
		http.Error(w, "unknown or missing mode argument", 400)
		return
	case "getchallenge":
		t := time.Now()
		fmt.Fprintf(w, "%s/%d/%s\n", serverName, t.Unix(), challengeAnswer(s.key, serverName, t))
		return
	case "getcert":
	}

	// Verify serverName resolves to a local IP.
	lookupCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var resolver net.Resolver
	resolver.PreferGo = true
	addrs, err := resolver.LookupHost(lookupCtx, serverName)
	if err != nil {
		log.Printf("autocertdelegate: lookup %q error: %v", serverName, err)
		badServerName(w)
		return
	}
	if len(addrs) != 1 {
		log.Printf("autocertDelegate: invalid server name %q; wrong number of resolved addrs. Want 1; got: %q", serverName, addrs)
		badServerName(w)
		return
	}
	challengeIP := addrs[0]
	if !validChallengeAddr(challengeIP) {
		log.Printf("autocertDelegate: server name %q resolved to invalid challenge IP %q", serverName, challengeIP)
		badServerName(w)
		return
	}

	challengePort, err := strconv.Atoi(r.FormValue("challengeport"))
	if err != nil || challengePort < 0 || challengePort > 64<<10 {
		http.Error(w, "invalid challengeport param", 400)
		return
	}
	challengeScheme := r.FormValue("challengescheme")
	switch challengeScheme {
	case "http", "https":
	case "":
		challengeScheme = "http"
	default:
		http.Error(w, "invalid challengescheme param", 400)
		return
	}
	challengeURL := fmt.Sprintf("%s://%s:%d/.well-known/autocertdelegate-challenge",
		challengeScheme, challengeIP, challengePort)

	if err := s.verifyChallengeURL(r.Context(), challengeURL, serverName); err != nil {
		log.Printf("autocertdelegate: failed challenge for %q: %v", serverName, err)
		badServerName(w)
		return
	}

	wantRSA, _ := strconv.ParseBool(r.FormValue("rsa"))

	var cipherSuites []uint16
	if !wantRSA {
		cipherSuites = append(cipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
	}
	// Prime the cache:
	if _, err := s.am.GetCertificate(&tls.ClientHelloInfo{
		ServerName:   r.FormValue("servername"),
		CipherSuites: cipherSuites,
	}); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	key := serverName
	if wantRSA {
		key += "+rsa"
	}
	// But what we really want is the on-disk PEM representation:
	pems, err := s.am.Cache.Get(r.Context(), key)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(pems)
}

func (s *Server) verifyChallengeURL(ctx context.Context, challengeURL, serverName string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", challengeURL, nil)
	if err != nil {
		log.Printf("autocertdelegate: verifyChallengeURL: new request: %v", err)
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("autocertdelegate: fetch %v: %v", challengeURL, err)
		return err
	}
	defer res.Body.Close()
	slurp, err := ioutil.ReadAll(io.LimitReader(res.Body, 4<<10))
	if err != nil {
		return err
	}
	f := strings.SplitN(strings.TrimSpace(string(slurp)), "/", 3)
	if len(f) != 3 {
		return errors.New("wrong number of parts")
	}
	gotServerName, unixTimeStr, gotAnswer := f[0], f[1], f[2]
	if serverName != gotServerName {
		return errors.New("wrong server name")
	}
	unixTimeN, err := strconv.ParseInt(unixTimeStr, 10, 64)
	if err != nil {
		return err
	}
	ut := time.Unix(unixTimeN, 0)
	if ut.Before(time.Now().Add(-10 * time.Second)) {
		return errors.New("too old")
	}
	wantAnswer := challengeAnswer(s.key, serverName, ut)
	if wantAnswer != gotAnswer {
		return errors.New("wrong challenge answer")
	}
	return nil
}

// Client fetches certs from the Server.
// Its GetCertificate method is suitable for use by an HTTP server's
// TLSConfig.GetCertificate.
type Client struct {
	server string
	am     *autocert.Manager
}

// NewClient returns a new client fetching from the provided server hostname.
// The server must be a hostname only (without a scheme or path).
func NewClient(server string) *Client {
	c := &Client{
		server: server,
	}
	c.am = &autocert.Manager{
		Cache:      &delegateCache{c},
		Prompt:     autocert.AcceptTOS,
		HostPolicy: func(ctx context.Context, host string) error { return nil },
		Client: &acme.Client{
			HTTPClient: &http.Client{
				Transport: failTransport{},
			},
		},
	}
	return c
}

// GetCertificate fetches a certificate suitable for responding to the
// provided hello. The signature of GetCertificate is suitable for
// use by an HTTP server's TLSConfig.GetCertificate.
func (c *Client) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return c.am.GetCertificate(hello)
}

// TODO: configuration knobs as needed.
func (c *Client) httpClient() *http.Client      { return http.DefaultClient }
func (c *Client) getCertTimeout() time.Duration { return 10 * time.Second }

type delegateCache struct{ c *Client }

func (dc *delegateCache) Get(ctx context.Context, key string) ([]byte, error) {
	rsa := strings.HasSuffix(key, "+rsa")
	host := strings.TrimSuffix(key, "+rsa")

	ctx, cancel := context.WithTimeout(ctx, dc.c.getCertTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/?servername=%s&mode=getchallenge",
		dc.c.server, url.QueryEscape(host)), nil)
	if err != nil {
		return nil, err
	}
	res, err := dc.c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get challenge for %s: %v", host, err)
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		return nil, fmt.Errorf("failed to get challenge for %s: %v", host, res.Status)
	}
	const maxChalLen = 1 << 10
	challenge, err := ioutil.ReadAll(io.LimitReader(res.Body, maxChalLen+1))
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read challenge for %s: %v", host, err)
	}
	if len(challenge) > maxChalLen || bytes.Count(challenge, []byte("\n")) > 1 {
		return nil, fmt.Errorf("challenge for %s doesn't look like a challenge", host)
	}

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(challenge)
		}),
	}
	go srv.Serve(ln)

	req, err = http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/?servername=%s&mode=getcert&rsa=%v&challengeport=%d&challengescheme=http",
		dc.c.server, url.QueryEscape(host), rsa, port),
		nil)
	if err != nil {
		return nil, err
	}
	res, err = dc.c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert for %s: %v", host, err)
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		return nil, fmt.Errorf("failed to get cert for %s: %v", host, res.Status)
	}
	defer res.Body.Close()
	slurp, err := ioutil.ReadAll(io.LimitReader(res.Body, 1<<20))
	return slurp, err
}

func (c *delegateCache) Put(ctx context.Context, key string, data []byte) error { return nil }

func (c *delegateCache) Delete(ctx context.Context, key string) error { return nil }

type failTransport struct{}

func (failTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	log.Printf("Not doing ACME request: %s", r.URL.String())
	return nil, errors.New("network request denied")
}
