//go:build js

package main

import (
	"net"
	"syscall/js"
	"testing"
)

// close and abort are terminal: after either one the connection's callbacks
// are released, so JavaScript can no longer reach the conn through them and Go
// no longer retains it.
func TestJSConnTerminalCallsReleaseCallbacks(t *testing.T) {
	for _, terminal := range []string{"close", "abort"} {
		t.Run(terminal, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			closed := 0
			conn := makeJSConn(a, 1, func() { closed++ })
			p := conn.Call("read")
			if p.Type() != js.TypeObject || p.Get("then").Type() != js.TypeFunction {
				t.Fatalf("read before %s did not return a promise", terminal)
			}
			// The pending read settles (or rejects) when the pipe closes.
			p.Call("catch", js.Global().Get("Function").New(""))
			conn.Call(terminal)
			if closed != 1 {
				t.Fatalf("onClose ran %d times", closed)
			}
			for _, name := range []string{"read", "write", "closeWrite", "close", "abort"} {
				if v := conn.Call(name); !v.IsUndefined() {
					t.Fatalf("%s still reachable after %s: %v", name, terminal, v.Type())
				}
			}
			if closed != 1 {
				t.Fatalf("released close/abort reached onClose again (%d)", closed)
			}
		})
	}
}
