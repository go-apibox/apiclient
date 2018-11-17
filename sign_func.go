package apiclient

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"net/url"
	"sort"
)

// MakeSign return the signature of url values signed by
// hmac/md5 with specified sign key.
func MakeSign(values url.Values, key string) []byte {
	values.Del("api_sign")
	qs := []byte(EncodeValues(values))
	mac := hmac.New(md5.New, []byte(key))
	mac.Write(qs)
	return mac.Sum(nil)
}

// MakeSignString return the signature of url values as string
// signed by hmac/md5 with specified sign key.
func MakeSignString(values url.Values, key string) string {
	t := MakeSign(values, key)
	return hex.EncodeToString(t)
}

// CheckSign return true if specified sign is the signature
// of url values.
func CheckSign(values url.Values, key string, sign []byte) bool {
	expected := MakeSignString(values, key)
	return hmac.Equal([]byte(expected), []byte(sign))
}

// EncodeValues encodes the values into "URL encoded" form
// ("bar=baz&foo=quux") sorted by key and values.
// Changed from url.Values.Encode()
func EncodeValues(v url.Values) string {
	if v == nil {
		return ""
	}
	var buf bytes.Buffer
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		// we add this
		// clone and sort
		// vs:=v[k]
		vs := make([]string, 0, len(v[k]))
		for _, x := range v[k] {
			vs = append(vs, x)
		}
		sort.Strings(vs)

		prefix := url.QueryEscape(k) + "="
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(prefix)
			buf.WriteString(url.QueryEscape(v))
		}
	}
	return buf.String()
}
