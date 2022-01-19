package jwt

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// pair lookup token pair
type pair struct {
	key   string
	value string
}

type Lookup struct {
	// headerName is a string in the header.
	// Default value is "Bearer"
	headerName string
	// lookup pair slice from lookup parse
	lookups []pair
}

// NewLookup new lookup
// lookup is a string in the form of "<source>:<name>" that is used
// to extract token from the request.
// use like "header:<name>,query:<name>,cookie:<name>"
// Optional, Default value "header:Authorization".
// Possible values:
// - "header:<name>"
// - "query:<name>"
// - "cookie:<name>"
// headerName is a string in the header.
// Possible value is "Bearer"
func NewLookup(lookup, headerName string) *Lookup {
	if lookup == "" {
		lookup = "header:Authorization"
	}
	headerName = strings.TrimSpace(headerName)
	methods := strings.Split(lookup, ",")
	lookups := make([]pair, 0, len(methods))
	for _, method := range methods {
		parts := strings.Split(strings.TrimSpace(method), ":")
		if len(parts) != 2 {
			continue
		}
		lookups = append(lookups, pair{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])})
	}
	return &Lookup{
		headerName,
		lookups,
	}
}

// GetToken 获取token, 从Request中获取,由 Lookup 定义
func (sf *Lookup) GetToken(c *gin.Context) (string, error) {
	var token string
	var err error

	for _, lookup := range sf.lookups {
		if len(token) > 0 {
			break
		}
		switch lookup.key {
		case "header":
			token, err = FromHeader(c, lookup.value, sf.headerName)

		case "query":
			token, err = FromQuery(c, lookup.value)
		case "cookie":
			token, err = FromCookie(c, lookup.value)
		case "param":
			token, err = FromParam(c, lookup.value)
		}
	}
	if err != nil {
		return "", err
	}
	if len(token) == 0 {
		return "", ErrMissingToken
	}
	return token, nil
}

// FromHeader get token from header
// key is header key, like "Authorization"
// headerName is a string in the header, like "Bearer", if it is empty, it will return value.
func FromHeader(c *gin.Context, key, headerName string) (string, error) {
	authHeader := c.Request.Header.Get(key)
	if authHeader == "" {
		return "", ErrMissingToken
	}
	if headerName == "" {
		return strings.TrimSpace(authHeader), nil
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == headerName) {
		return "", ErrInvalidAuthHeader
	}
	return strings.TrimSpace(parts[1]), nil
}

// FromQuery get token from query
// key is query key
func FromQuery(c *gin.Context, key string) (string, error) {
	token := c.Query(key)
	if token == "" {
		return "", ErrMissingToken
	}
	return strings.TrimSpace(token), nil
}

// FromCookie get token from Cookie
// key is cookie key
func FromCookie(c *gin.Context, key string) (string, error) {
	cookie, _ := c.Cookie(key)
	if cookie == "" {
		return "", ErrMissingToken
	}
	return strings.TrimSpace(cookie), nil
}

// FromParam get token from param
// key is param key
func FromParam(c *gin.Context, key string) (string, error) {
	token := c.Param(key)
	if token == "" {
		return "", ErrMissingToken
	}
	return strings.TrimSpace(token), nil
}
