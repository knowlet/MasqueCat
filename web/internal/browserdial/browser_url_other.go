// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package browserdial

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// browserIDNA matches the URL Standard's non-strict domain-to-ASCII profile:
// CheckHyphens, UseSTD3ASCIIRules, and VerifyDnsLength are false;
// CheckBidi and CheckJoiners are true; transitional processing is off.
var browserIDNA = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
	idna.StrictDomainName(false),
	idna.CheckHyphens(false),
	idna.VerifyDNSLength(false),
	idna.CheckJoiners(true),
)

// browserCanParseURL approximates the browser URL parser for native tests.
// The js/wasm build asks the host URL parser instead.
func browserCanParseURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	if port := u.Port(); port != "" {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return false
		}
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if strings.Contains(host, ":") {
		// The URL Standard has no zone identifiers. netip accepts them.
		addr, err := netip.ParseAddr(host)
		return err == nil && addr.Is6() && addr.Zone() == ""
	}
	decoded, err := url.PathUnescape(host)
	if err != nil || decoded == "" || !utf8.ValidString(decoded) {
		return false
	}
	ascii, ok := browserDomainToASCII(decoded)
	if !ok {
		return false
	}
	if endsInNumber(ascii) {
		return ipv4Parsable(ascii)
	}
	return true
}

// browserDomainToASCII follows the URL Standard domain parser with beStrict
// false. ASCII domains are lowercased even when ToASCII would fail; non-ASCII
// domains must pass the relaxed ToASCII profile.
func browserDomainToASCII(domain string) (string, bool) {
	if domain == "" {
		return "", false
	}
	var ascii string
	if isASCII(domain) {
		ascii = strings.ToLower(domain)
	} else {
		var err error
		ascii, err = browserIDNA.ToASCII(domain)
		if err != nil || ascii == "" {
			return "", false
		}
	}
	if ascii == "" || strings.IndexFunc(ascii, forbiddenDomainRune) >= 0 {
		return "", false
	}
	return ascii, true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// forbiddenDomainRune reports URL Standard forbidden domain code points.
func forbiddenDomainRune(r rune) bool {
	switch r {
	case ' ', '#', '/', ':', '<', '>', '?', '@', '[', '\\', ']', '^', '|', '%', 0x7f:
		return true
	}
	return r <= 0x1f
}

func endsInNumber(input string) bool {
	parts := strings.Split(input, ".")
	if len(parts) == 0 {
		return false
	}
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return false
	}
	last := parts[len(parts)-1]
	if last != "" && allASCIIDigits(last) {
		return true
	}
	_, ok := parseIPv4Number(last)
	return ok
}

func allASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func parseIPv4Number(input string) (uint64, bool) {
	if input == "" {
		return 0, false
	}
	radix := uint64(10)
	if len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X') {
		input = input[2:]
		radix = 16
	} else if len(input) >= 2 && input[0] == '0' {
		input = input[1:]
		radix = 8
	}
	if input == "" {
		return 0, true
	}
	var n uint64
	for i := 0; i < len(input); i++ {
		c := input[i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, false
		}
		if d >= radix {
			return 0, false
		}
		if n > (^uint64(0)-d)/radix {
			return 0, false
		}
		n = n*radix + d
	}
	return n, true
}

func ipv4Parsable(input string) bool {
	parts := strings.Split(input, ".")
	if len(parts) > 0 && parts[len(parts)-1] == "" && len(parts) > 1 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 || len(parts) > 4 {
		return false
	}
	numbers := make([]uint64, len(parts))
	for i, part := range parts {
		n, ok := parseIPv4Number(part)
		if !ok {
			return false
		}
		numbers[i] = n
	}
	for i := 0; i < len(numbers)-1; i++ {
		if numbers[i] > 255 {
			return false
		}
	}
	last := numbers[len(numbers)-1]
	limit := uint64(1)
	for i := 0; i < 5-len(numbers); i++ {
		limit *= 256
	}
	return last < limit
}
