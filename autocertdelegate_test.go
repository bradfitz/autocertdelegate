// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package autocertdelegate

import "testing"

func TestValidChallengeAddr(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"10.0.0.1", true},
		{"192.168.5.2", true},
		{"8.8.8.8", false},
		{"", false},
		{"::1", false}, // yet
	}
	for _, tt := range tests {
		got := validChallengeAddr(tt.name)
		if got != tt.want {
			t.Errorf("validChallengeAddr(%q) = %v; want %v", tt.name, got, tt.want)
		}
	}
}

func TestValidDelegateServerName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"", false},
		{"foo", false},
		{"::1", false},
		{"foo.com:123", false},
		{"8.8.8.8", false},
		{"cams.int.example.net", true},
		{"cams.int.example.net/foo", false},
	}
	for _, tt := range tests {
		got := validDelegateServerName(tt.name)
		if got != tt.want {
			t.Errorf("validDelegateServerName(%q) = %v; want %v", tt.name, got, tt.want)
		}
	}
}
