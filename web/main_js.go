// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The tailcat web app is the WebAssembly (js/wasm) build used by the browser
// demo. Legacy tc... addresses still use DERP over WebSockets. MasqueCat mc...
// addresses use BrowserMasqueClient: WebTransport to a MasqueCat relay with the
// same userspace WireGuard + gVisor application data plane as native peers.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"syscall/js"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func main() {
	js.Global().Set("tailcatListen", js.FuncOf(tailcatListen))
	js.Global().Set("tailcatDial", js.FuncOf(tailcatDial))
	if f := js.Global().Get("onTailcatReady"); f.Type() == js.TypeFunction {
		f.Invoke()
	}
	select {}
}

// tailcatListen starts the legacy Tailcat server in the browser. Browser-side
// MasqueCat listen/server mode is not implemented yet; mc... support currently
// covers the client/send path through a WebTransport-capable MasqueCat relay.
func tailcatListen(this js.Value, args []js.Value) any {
	if len(args) != 1 || args[0].Type() != js.TypeObject {
		return rejectedPromise(errors.New("tailcatListen requires an options object"))
	}
	opts := args[0]
	onConnection := opts.Get("onConnection")
	derpMapURL := optString(opts, "derpMapURL")
	keyJSON := optString(opts, "privateKey")
	logf := optLogf(opts)
	return makePromise(func() (any, error) {
		if onConnection.Type() != js.TypeFunction {
			return nil, errors.New("onConnection function is required")
		}
		if derpMapURL == "" {
			return nil, errors.New("derpMapURL is required for legacy browser listener mode")
		}
		pk := &tailcat.PrivateKey{}
		if keyJSON != "" {
			if err := json.Unmarshal([]byte(keyJSON), pk); err != nil {
				return nil, fmt.Errorf("parsing privateKey: %w", err)
			}
		} else {
			pk = tailcat.NewPrivateKey()
			pk.Public.RegionID = -1
		}
		if pk.Public.PresharedKey.IsZero() {
			// Migrate private keys saved by versions predating WireGuard PSKs.
			// The returned privateKeyJSON persists the new address capability.
			pk.Public.PresharedKey = tailcat.NewPresharedKey()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ci := pk.Public
		if err := ci.Expand(ctx, tailcat.ExpandForServer, tailcat.DERPMapURL(derpMapURL)); err != nil {
			return nil, fmt.Errorf("Expand: %w", err)
		}
		reg := ci.Region[0]
		if keyJSON == "" {
			pk.Public.RegionID = reg.RegionID
		}
		addr := pk.Public.Addr()
		keyOut, err := json.Marshal(pk)
		if err != nil {
			return nil, err
		}

		srv := &tailcat.Server{Key: pk.Private, PresharedKey: pk.Public.PresharedKey, Logf: logf, Region: reg}
		srv.OnTCP = func(port uint16) (handler func(net.Conn)) {
			return func(c net.Conn) { onConnection.Invoke(makeJSConn(c, port, nil)) }
		}
		if err := srv.Start(); err != nil {
			srv.Close()
			return nil, fmt.Errorf("Server.Start: %w", err)
		}
		return map[string]any{
			"addr":           string(addr),
			"privateKeyJSON": string(keyOut),
			"close": js.FuncOf(func(this js.Value, args []js.Value) any {
				srv.Close()
				return nil
			}),
		}, nil
	})
}

// tailcatDial accepts both legacy tc... and MasqueCat mc... addresses. mc...
// addresses require a relay URL in the token because browsers cannot originate
// arbitrary CONNECT-UDP requests; the relay exposes an authenticated
// WebTransport ingress for browser peers.
func tailcatDial(this js.Value, args []js.Value) any {
	if len(args) != 1 || args[0].Type() != js.TypeObject {
		return rejectedPromise(errors.New("tailcatDial requires an options object"))
	}
	opts := args[0]
	addr := optString(opts, "addr")
	derpMapURL := optString(opts, "derpMapURL")
	keyJSON := optString(opts, "privateKey")
	logf := optLogf(opts)
	port := uint16(1)
	if p := opts.Get("port"); p.Type() == js.TypeNumber {
		port = uint16(p.Int())
	}
	return makePromise(func() (any, error) {
		if addr == "" {
			return nil, errors.New("addr is required")
		}
		priv := key.NewNode()
		if keyJSON != "" {
			var pk tailcat.PrivateKey
			if err := json.Unmarshal([]byte(keyJSON), &pk); err != nil {
				return nil, fmt.Errorf("parsing privateKey: %w", err)
			}
			priv = pk.Private
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		if strings.HasPrefix(addr, "mc") {
			cl := tailcat.NewBrowserMasqueClient(tailcat.MasqueConnBlob(addr), priv, logf)
			if err := pingUntil(ctx, cl.Ping); err != nil {
				cl.Close()
				return nil, err
			}
			c, err := cl.DialTCPPort(ctx, port)
			if err != nil {
				cl.Close()
				return nil, fmt.Errorf("MasqueCat DialTCPPort: %w", err)
			}
			return makeJSConn(c, port, func() { _ = cl.Close() }), nil
		}

		cl := &tailcat.Client{
			Server:     tailcat.Addr(addr),
			Key:        priv,
			Logf:       logf,
			DERPMapURL: derpMapURL,
		}
		if err := pingUntil(ctx, cl.Ping); err != nil {
			cl.Close()
			return nil, err
		}
		c, err := cl.DialTCPPort(ctx, port)
		if err != nil {
			cl.Close()
			return nil, fmt.Errorf("DialTCPPort: %w", err)
		}
		return makeJSConn(c, port, func() { cl.Close() }), nil
	})
}

func pingUntil(ctx context.Context, ping func(context.Context) (tailcat.PingResult, error)) error {
	for {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := ping(pctx)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("ping: %w", err)
		}
	}
}

func makeJSConn(c net.Conn, port uint16, onClose func()) js.Value {
	buf := make([]byte, 64<<10)
	return js.ValueOf(map[string]any{
		"port": int(port),
		"read": js.FuncOf(func(this js.Value, args []js.Value) any {
			return makePromise(func() (any, error) {
				n, err := c.Read(buf)
				if n > 0 {
					u8 := js.Global().Get("Uint8Array").New(n)
					js.CopyBytesToJS(u8, buf[:n])
					return u8, nil
				}
				if err == nil || errors.Is(err, io.EOF) {
					return js.Null(), nil
				}
				return nil, err
			})
		}),
		"write": js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) != 1 {
				return rejectedPromise(errors.New("write requires a Uint8Array"))
			}
			b := make([]byte, args[0].Get("length").Int())
			js.CopyBytesToGo(b, args[0])
			return makePromise(func() (any, error) {
				if _, err := c.Write(b); err != nil {
					return nil, err
				}
				return js.Undefined(), nil
			})
		}),
		"closeWrite": js.FuncOf(func(this js.Value, args []js.Value) any {
			return makePromise(func() (any, error) {
				cw, ok := c.(interface{ CloseWrite() error })
				if !ok {
					return nil, errors.New("connection does not support half-close")
				}
				if err := cw.CloseWrite(); err != nil {
					return nil, err
				}
				return js.Undefined(), nil
			})
		}),
		"close": js.FuncOf(func(this js.Value, args []js.Value) any {
			c.Close()
			if onClose != nil {
				onClose()
			}
			return nil
		}),
	})
}

func optString(v js.Value, name string) string {
	if p := v.Get(name); p.Type() == js.TypeString {
		return p.String()
	}
	return ""
}

func optLogf(v js.Value) logger.Logf {
	if v.Get("verbose").Truthy() {
		return log.Printf
	}
	return logger.Discard
}

func makePromise(f func() (any, error)) js.Value {
	handler := js.FuncOf(func(this js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			if res, err := f(); err == nil {
				resolve.Invoke(res)
			} else {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
			}
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

func rejectedPromise(err error) js.Value {
	return js.Global().Get("Promise").Call("reject", js.Global().Get("Error").New(err.Error()))
}
