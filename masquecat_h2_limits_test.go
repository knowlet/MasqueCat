//go:build !js

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
	// http2.Framer.readMetaFrame bounds each decoded HPACK string using
	// MaxHeaderListSize, overriding any lower decoder-local string limit.
	block := encodeH2HeaderBlock(t, []hpack.HeaderField{{
		Name:  "x-oversize",
		Value: strings.Repeat("a", int(masqueH2MaxHeaderListSize)+1),
	}})
	meta, err := readH2MetaHeaders(t, block)
	if err == nil && (meta == nil || !meta.Truncated) {
		t.Fatal("oversize HPACK string was accepted without truncation")
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
