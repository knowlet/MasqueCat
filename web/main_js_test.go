//go:build js

package main

import (
	"net"
	"syscall/js"
	"testing"
	"time"
)

// await blocks the test goroutine until p settles. While it waits, the Go
// runtime yields to the JavaScript event loop, which runs promise callbacks.
func await(t *testing.T, p js.Value) {
	t.Helper()
	if p.Type() != js.TypeObject || p.Get("then").Type() != js.TypeFunction {
		t.Fatalf("expected a promise, got %v", p.Type())
	}
	done := make(chan struct{})
	settle := js.FuncOf(func(this js.Value, args []js.Value) any {
		close(done)
		return nil
	})
	defer settle.Release()
	p.Call("then", settle, settle)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("promise did not settle")
	}
}

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
			await(t, conn.Call(terminal))
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

// Client shutdown can wait on a JavaScript promise (a pending WireGuard send).
// If close/abort ran that teardown inside the JavaScript callback, the promise
// could never settle and the page would freeze.
func TestJSConnTeardownMayWaitOnJavaScriptPromises(t *testing.T) {
	for _, terminal := range []string{"close", "abort"} {
		t.Run(terminal, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			tornDown := make(chan struct{})
			conn := makeJSConn(a, 1, func() {
				settled := make(chan struct{})
				then := js.FuncOf(func(this js.Value, args []js.Value) any {
					close(settled)
					return nil
				})
				defer then.Release()
				js.Global().Get("Promise").Call("resolve").Call("then", then)
				<-settled
				close(tornDown)
			})
			// Call the terminal method the way JavaScript does, from a callback.
			invoke := js.Global().Get("Function").New("conn", "name",
				"return Promise.resolve().then(() => conn[name]())")
			await(t, invoke.Invoke(conn, terminal))
			select {
			case <-tornDown:
			case <-time.After(5 * time.Second):
				t.Fatal("teardown never finished")
			}
		})
	}
}
