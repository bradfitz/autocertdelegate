# autocertdelegate

## What

[I wanted](https://twitter.com/bradfitz/status/1206058552357355520)
internal HTTPS servers to have valid TLS certs with minimal fuss.

In particular:

* I didn't want to deal with being my own CA or configuring all my
  devices to trust a new root.
* I didn't want to use LetsEncrypt DNS challenges because there are
  tons of DNS providers and I don't want API clients for tons of DNS
  providers and I don't want to configure secrets (or anything)
  anywhere.
* I don't want to expose my internal services to the internet or deal
  with updating firewall rules to only allow LetsEncrypt.

## How

See https://godoc.org/github.com/bradfitz/autocertdelegate

It provides a client that plugs in to an http.Server to get certs & a
server handler for a public-facing server that does the LetsEncrypt
ALPN challenges. You then do split-horizon DNS to give out internal
IPs to internal clients and a public IP (of the delegate server) to
everybody else (namely LetsEncrypt doing the ALPN challenges).

Then internal clients just ask the delegate server for the certs, and
the delegate server does a little challenge itself to test the
internal clients.

## Is it secure?

I built this for my own use on my home network.
Maybe you'll find it useful, but maybe you'll find it insecure.
Beauty is in the eye of the downloader.

## Contributing

I'm releasing as a Go project under the Go AUTHORs/LICENSEs, as it's
related to golang.org/x/crypto/acme/autocert. As such, I'm not
accepting any PRs unless you've contributed to Go or otherwise done
the Google CLA.
