package jwt

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Cookie for cookie set jwt token
type Cookie struct {
	// For cookie
	// Duration that a cookie is valid.
	CookieMaxAge time.Duration
	// Allow insecure cookies for development over http
	SecureCookie bool
	// Allow cookies to be accessed client side for development
	CookieHTTPOnly bool
	// Allow cookie domain change for development
	CookieDomain string
	// CookieName allow cookie name change for development
	CookieName string
	// CookieSameSite allow use http.SameSite cookie param
	CookieSameSite http.SameSite
}

// SetCookie can be used by clients to set the jwt cookie
func (sf *Cookie) SetCookie(c *gin.Context, tokenString string) {
	if sf.CookieSameSite != 0 {
		c.SetSameSite(sf.CookieSameSite)
	}
	c.SetCookie(
		sf.CookieName, tokenString, int(sf.CookieMaxAge/time.Second),
		"/", sf.CookieDomain, sf.SecureCookie, sf.CookieHTTPOnly,
	)
}

// RemoveCookie can be used by clients to remove the jwt cookie (if set)
func (sf *Cookie) RemoveCookie(c *gin.Context) {
	if sf.CookieSameSite != 0 {
		c.SetSameSite(sf.CookieSameSite)
	}
	c.SetCookie(
		sf.CookieName, "", -1,
		"/", sf.CookieDomain, sf.SecureCookie, sf.CookieHTTPOnly,
	)
}
