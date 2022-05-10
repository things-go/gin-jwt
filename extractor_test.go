package jwt

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v4/request"
)

func TestExtractor(t *testing.T) {
	var extractorTestTokenValue = "testTokenValue"

	var tests = []struct {
		name      string
		extractor request.Extractor
		headers   map[string]string
		query     url.Values
		cookie    map[string]string
		token     string
		err       error
	}{
		{
			name:      "header hit",
			extractor: HeaderExtractor{"token", ""},
			headers:   map[string]string{"token": extractorTestTokenValue},
			query:     nil,
			cookie:    nil,
			token:     extractorTestTokenValue,
			err:       nil,
		},
		{
			name:      "header miss",
			extractor: HeaderExtractor{"This-Header-Is-Not-Set", ""},
			headers:   map[string]string{"token": extractorTestTokenValue},
			query:     nil,
			cookie:    nil,
			token:     "",
			err:       ErrMissingToken,
		},

		{
			name:      "header filter",
			extractor: HeaderExtractor{"Authorization", "Bearer"},
			headers:   map[string]string{"Authorization": "Bearer " + extractorTestTokenValue},
			query:     nil,
			cookie:    nil,
			token:     extractorTestTokenValue,
			err:       nil,
		},
		{
			name:      "header filter miss",
			extractor: HeaderExtractor{"Authorization", "Bearer"},
			headers:   map[string]string{"Authorization": "Bearer   "},
			query:     nil,
			cookie:    nil,
			token:     "",
			err:       ErrMissingToken,
		},
		{
			name:      "argument hit",
			extractor: ArgumentExtractor("token"),
			headers:   map[string]string{},
			query:     url.Values{"token": {extractorTestTokenValue}},
			cookie:    nil,
			token:     extractorTestTokenValue,
			err:       nil,
		},
		{
			name:      "argument miss",
			extractor: ArgumentExtractor("token"),
			headers:   map[string]string{},
			query:     nil,
			cookie:    nil,
			token:     "",
			err:       ErrMissingToken,
		},
		{
			name:      "cookie hit",
			extractor: CookieExtractor("token"),
			headers:   map[string]string{},
			query:     nil,
			cookie:    map[string]string{"token": extractorTestTokenValue},
			token:     extractorTestTokenValue,
			err:       nil,
		},
		{
			name:      "cookie miss",
			extractor: ArgumentExtractor("token"),
			headers:   map[string]string{},
			query:     nil,
			cookie:    map[string]string{},
			token:     "",
			err:       ErrMissingToken,
		},
		{
			name:      "cookie miss",
			extractor: ArgumentExtractor("token"),
			headers:   map[string]string{},
			query:     nil,
			cookie:    map[string]string{"token": " "},
			token:     "",
			err:       ErrMissingToken,
		},
	}
	// Bearer token request
	for _, e := range tests {
		// Make request from test struct
		r := makeTestRequest("GET", "/", e.headers, e.cookie, e.query)

		// Test extractor
		token, err := e.extractor.ExtractToken(r)
		if token != e.token {
			t.Errorf("[%v] Expected token '%v'.  Got '%v'", e.name, e.token, token)
			continue
		}
		if err != e.err {
			t.Errorf("[%v] Expected error '%v'.  Got '%v'", e.name, e.err, err)
			continue
		}
	}
}

func makeTestRequest(method, path string, headers, cookie map[string]string, urlArgs url.Values) *http.Request {
	r, _ := http.NewRequest(method, fmt.Sprintf("%v?%v", path, urlArgs.Encode()), nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	for k, v := range cookie {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	return r
}
