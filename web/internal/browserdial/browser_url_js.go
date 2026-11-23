// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js

package browserdial

import "syscall/js"

// browserCanParseURL reports whether the browser URL parser accepts raw.
// WebTransport uses that parser and throws synchronously when it fails.
func browserCanParseURL(raw string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	ctor := js.Global().Get("URL")
	if ctor.Type() != js.TypeFunction {
		// No URL constructor in this runtime. The WebTransport call site
		// recovers from the constructor exception instead.
		return true
	}
	if ctor.Get("canParse").Type() == js.TypeFunction {
		return ctor.Call("canParse", raw).Bool()
	}
	ctor.New(raw)
	return true
}
