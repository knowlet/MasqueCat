from pathlib import Path


def replace_once(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one {label}, found {count}")
    p.write_text(text.replace(old, new, 1))


replace_once(
    "masquecat_h2.go",
    '''\tmasqueH2InitialWindow   = uint32(1 << 20)\n\tmasqueH2ReadIdleTimeout = 30 * time.Second\n''',
    '''\tmasqueH2InitialWindow         = uint32(1 << 20)\n\tmasqueH2MaxHeaderListSize     = uint32(64 << 10)\n\tmasqueH2MaxHeaderStringLength = 16 << 10\n\tmasqueH2ReadIdleTimeout       = 30 * time.Second\n''',
    "HTTP/2 constants block",
)

replace_once(
    "masquecat_h2.go",
    '''\tc.fr = http2.NewFramer(conn, conn)\n\tc.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)\n\n\tif err := c.writeSettings(); err != nil {\n''',
    '''\tc.fr = newMasqueH2Framer(conn, conn)\n\n\tif err := c.writeSettings(); err != nil {\n''',
    "server framer construction",
)

replace_once(
    "masquecat_h2.go",
    '''func (c *masqueHTTP2Conn) writeSettings() error {\n\tif err := c.writeFrame(func() error {\n\t\treturn c.fr.WriteSettings(\n\t\t\thttp2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1},\n\t\t\thttp2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1},\n\t\t\thttp2.Setting{ID: http2.SettingInitialWindowSize, Val: masqueH2InitialWindow},\n\t\t)\n''',
    '''func newMasqueH2Framer(w io.Writer, r io.Reader) *http2.Framer {\n\tfr := http2.NewFramer(w, r)\n\tdecoder := hpack.NewDecoder(4096, nil)\n\tdecoder.SetMaxStringLength(masqueH2MaxHeaderStringLength)\n\tfr.ReadMetaHeaders = decoder\n\tfr.MaxHeaderListSize = masqueH2MaxHeaderListSize\n\treturn fr\n}\n\nfunc (c *masqueHTTP2Conn) writeSettings() error {\n\tif err := c.writeFrame(func() error {\n\t\treturn c.fr.WriteSettings(\n\t\t\thttp2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1},\n\t\t\thttp2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1},\n\t\t\thttp2.Setting{ID: http2.SettingInitialWindowSize, Val: masqueH2InitialWindow},\n\t\t\thttp2.Setting{ID: http2.SettingMaxHeaderListSize, Val: masqueH2MaxHeaderListSize},\n\t\t)\n''',
    "server settings function",
)

replace_once(
    "masquecat_h2.go",
    '''\t\tcase *http2.MetaHeadersFrame:\n\t\t\tif c.streamID != 0 {\n''',
    '''\t\tcase *http2.MetaHeadersFrame:\n\t\t\tif f.Truncated {\n\t\t\t\treturn errors.New("masquecat: HTTP/2 request headers exceed configured limit")\n\t\t\t}\n\t\t\tif c.streamID != 0 {\n''',
    "server MetaHeaders handling",
)

replace_once(
    "masquecat_h2_client.go",
    '''\tcc.fr = http2.NewFramer(nc, nc)\n\tcc.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)\n\n\tif err := cc.writeClientPrefaceAndSettings(); err != nil {\n''',
    '''\tcc.fr = newMasqueH2Framer(nc, nc)\n\n\tif err := cc.writeClientPrefaceAndSettings(); err != nil {\n''',
    "client framer construction",
)

replace_once(
    "masquecat_h2_client.go",
    '''\tif err := c.fr.WriteSettings(\n\t\thttp2.Setting{ID: http2.SettingInitialWindowSize, Val: masqueH2InitialWindow},\n\t\thttp2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1},\n\t); err != nil {\n''',
    '''\tif err := c.fr.WriteSettings(\n\t\thttp2.Setting{ID: http2.SettingInitialWindowSize, Val: masqueH2InitialWindow},\n\t\thttp2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1},\n\t\thttp2.Setting{ID: http2.SettingMaxHeaderListSize, Val: masqueH2MaxHeaderListSize},\n\t); err != nil {\n''',
    "client settings",
)

replace_once(
    "masquecat_h2_client.go",
    '''\t\tcase *http2.MetaHeadersFrame:\n\t\t\tif f.StreamID != c.streamID || c.streamID == 0 {\n''',
    '''\t\tcase *http2.MetaHeadersFrame:\n\t\t\tif f.Truncated {\n\t\t\t\terr = errors.New("masquecat: HTTP/2 response headers exceed configured limit")\n\t\t\t\treturn\n\t\t\t}\n\t\t\tif f.StreamID != c.streamID || c.streamID == 0 {\n''',
    "client MetaHeaders handling",
)

client = Path("masquecat_h2_client.go")
text = client.read_text()
text = text.replace('\n\t"golang.org/x/net/http2/hpack"', '')
client.write_text(text)

Path("masquecat_h2_limits_test.go").write_text(r'''//go:build !js

package tailcat

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func encodeH2HeaderBlock(t *testing.T, fields []hpack.HeaderField) []byte {
	t.Helper()
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, field := range fields {
		if err := enc.WriteField(field); err != nil {
			t.Fatalf("encode header field: %v", err)
		}
	}
	return block.Bytes()
}

func readH2MetaHeaders(t *testing.T, block []byte) (*http2.MetaHeadersFrame, error) {
	t.Helper()
	var wire bytes.Buffer
	writer := http2.NewFramer(&wire, nil)
	if err := writer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: block,
		EndHeaders:    true,
	}); err != nil {
		t.Fatalf("write HEADERS: %v", err)
	}
	reader := newMasqueH2Framer(io.Discard, &wire)
	frame, err := reader.ReadFrame()
	if err != nil {
		return nil, err
	}
	meta, ok := frame.(*http2.MetaHeadersFrame)
	if !ok {
		t.Fatalf("frame type = %T, want *http2.MetaHeadersFrame", frame)
	}
	return meta, nil
}

func TestMasqueH2FramerRejectsOversizeHeaderString(t *testing.T) {
	block := encodeH2HeaderBlock(t, []hpack.HeaderField{{
		Name:  "x-oversize",
		Value: strings.Repeat("a", masqueH2MaxHeaderStringLength+1),
	}})
	if _, err := readH2MetaHeaders(t, block); err == nil {
		t.Fatal("oversize HPACK string was accepted")
	}
}

func TestMasqueH2FramerTruncatesOversizeHeaderList(t *testing.T) {
	fields := make([]hpack.HeaderField, 2000)
	for i := range fields {
		fields[i] = hpack.HeaderField{Name: "x", Value: "y"}
	}
	meta, err := readH2MetaHeaders(t, encodeH2HeaderBlock(t, fields))
	if err != nil {
		t.Fatal(err)
	}
	if !meta.Truncated {
		t.Fatal("oversize HTTP/2 header list was not marked truncated")
	}
}
''')
