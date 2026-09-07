//go:build !js

package tailcat

import "net/http"

// masqueProxyRequestForParser restores the absolute-URI authority that
// masque-go's ParseProxyRequest expects when matching its CONNECT-UDP URI
// template. The custom HTTP/2 frontend reconstructs a normal server-side
// http.Request from pseudo-headers, where :authority lives in Request.Host and
// URL.Host is empty. HTTP/3 requests already arrive in the representation
// masque-go expects and are returned unchanged.
func masqueProxyRequestForParser(r *http.Request) *http.Request {
	if r == nil || r.ProtoMajor != 2 || r.URL == nil || r.Host == "" || r.URL.Host != "" {
		return r
	}
	clone := r.Clone(r.Context())
	u := *r.URL
	u.Host = r.Host
	clone.URL = &u
	return clone
}
