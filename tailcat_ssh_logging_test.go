// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux || darwin || windows) && !ts_omit_ssh

package tailcat

import (
	"fmt"
	"testing"
)

func TestSSHLogfWithoutLocalBackend(t *testing.T) {
	var got string
	s := &Server{
		Logf: func(format string, args ...any) {
			got = fmt.Sprintf(format, args...)
		},
	}

	// MasqueServer uses the embedded Server without creating the legacy
	// localBackend. Logging SSH/SFTP errors must therefore be safe with lb nil.
	s.sshLogf("sftp session: %v", "protocol error")

	if want := "sftp session: protocol error"; got != want {
		t.Fatalf("sshLogf() = %q; want %q", got, want)
	}
}

func TestSSHLogfWithoutAnyLogger(t *testing.T) {
	s := &Server{}

	// The absence of both Server.Logf and the legacy localBackend logger must
	// degrade to no logging rather than panic.
	s.sshLogf("sftp session: %v", "protocol error")
}
