package jwt

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestCookie(t *testing.T) {
	t.Run("set cookies", func(t *testing.T) {
		cookie := Cookie{
			CookieMaxAge:   time.Second * 24,
			SecureCookie:   false,
			CookieHTTPOnly: false,
			CookieDomain:   "",
			CookieName:     "cookie",
			CookieSameSite: http.SameSiteDefaultMode,
		}

		req := httptest.NewRequest(http.MethodGet, "/get", nil)

		resp := httptest.NewRecorder()
		srv := gin.New()
		srv.GET("/get", func(c *gin.Context) {
			cookie.SetCookie(c, "xxxxxx")
		})
		srv.ServeHTTP(resp, req)
		ck := resp.Result().Cookies()[0]
		require.Equal(t, "xxxxxx", ck.Value)
		require.Equal(t, 24, ck.MaxAge)
	})
	t.Run("remove cookies", func(t *testing.T) {
		cookie := Cookie{
			CookieMaxAge:   time.Hour * 24,
			SecureCookie:   false,
			CookieHTTPOnly: false,
			CookieDomain:   "",
			CookieName:     "cookie",
			CookieSameSite: http.SameSiteDefaultMode,
		}

		req := httptest.NewRequest(http.MethodGet, "/get", nil)

		resp := httptest.NewRecorder()
		srv := gin.New()
		srv.GET("/get", func(c *gin.Context) {
			cookie.RemoveCookie(c)
		})
		srv.ServeHTTP(resp, req)
		ck := resp.Result().Cookies()[0]
		require.Equal(t, "", ck.Value)
		require.Equal(t, -1, ck.MaxAge)
	})
}
