//go:build !js

package tailcat

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"tailscale.com/types/key"
)

type masqueH2ClientResult struct {
	resp *http.Response
	err  error
}

type masqueH2ClientConn struct {
	conn net.Conn
	fr   *http2.Framer

	ctx    context.Context
	cancel context.CancelFunc

	writeMu sync.Mutex
	flowMu  sync.Mutex
	flowCh  chan struct{}

	done     chan struct{}
	closeOnce sync.Once

	peerConnWindow    int64
	peerStreamWindow  int64
	peerInitialWindow int64
	peerMaxFrameSize  uint32

	streamID uint32
	bodyR    *io.PipeReader
	bodyW    *io.PipeWriter

	settingsOnce          sync.Once
	settingsCh            chan error
	extendedConnectAllowed bool

	responseOnce sync.Once
	responseCh   chan masqueH2ClientResult
}

func dialMasqueH2PacketConnRFC8441(
	ctx context.Context,
	tmpl interface{ Expand(map[string]any) (string, error) },
	target key.NodePublic,
	local key.NodePrivate,
	mode string,
	tlsConfig *tls.Config,
) (net.PacketConn, error) {
	return nil, errors.New("unreachable")
}
