package jwt

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4/request"
)

// Lookup is a tool that looks up the token
type Lookup struct {
	extractors request.MultiExtractor
}

// NewLookup new lookup
// lookup is a string in the form of "<source>:<name>[:<prefix>]" that is used
// to extract token from the request.
// use like "header:<name>[:<prefix>],query:<name>,cookie:<name>,param:<name>"
// Optional, Default value "header:Authorization:Bearer".
// Possible values:
// - "header:<name>:<prefix>", <prefix> is a special string in the header, Possible value is "Bearer"
// - "query:<name>"
// - "cookie:<name>"
func NewLookup(lookup string) *Lookup {
	if lookup == "" {
		lookup = "header:Authorization:Bearer"
	}
	methods := strings.Split(lookup, ",")
	lookups := make(request.MultiExtractor, 0, len(methods))
	for _, method := range methods {
		parts := strings.Split(strings.TrimSpace(method), ":")
		if !(len(parts) == 2 || len(parts) == 3) {
			continue
		}
		switch parts[0] {
		case "header":
			prefix := ""
			if len(parts) == 3 {
				prefix = strings.TrimSpace(parts[2])
			}
			lookups = append(lookups, HeaderExtractor{strings.TrimSpace(parts[1]), prefix})
		case "query":
			lookups = append(lookups, ArgumentExtractor(parts[1]))
		case "cookie":
			lookups = append(lookups, CookieExtractor(parts[1]))
		}
	}
	return &Lookup{lookups}
}

// Get get token from header, defined in NewLookup
func (sf *Lookup) Get(r *http.Request) (string, error) {
	token, err := sf.extractors.ExtractToken(r)
	if err != nil || token == "" {
		return "", ErrMissingToken
	}
	return token, nil
}

// FromHeader get token from header
// key is header key, like "Authorization"
// prefix is a string in the header, like "Bearer", if it is empty, it will return value.
func FromHeader(r *http.Request, key, prefix string) (string, error) {
	return HeaderExtractor{key, prefix}.ExtractToken(r)
}

// FromQuery get token from query
// key is query key
func FromQuery(r *http.Request, key string) (string, error) {
	return ArgumentExtractor(key).ExtractToken(r)
}

// FromCookie get token from Cookie
// key is cookie key
func FromCookie(r *http.Request, key string) (string, error) {
	return CookieExtractor(key).ExtractToken(r)
}
