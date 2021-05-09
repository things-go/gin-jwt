package main

import (
	"log"
	"math/rand"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	jwt "github.com/things-go/gin-jwt"
)

const identityKey = "identify"

// User demo
type User struct {
	Uid      int64
	Username string
}

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

func main() {
	// jwt auth
	auth, err := jwt.New(jwt.Config{
		Key:        []byte("secret key"),
		Timeout:    time.Hour,
		MaxRefresh: time.Hour,
		// TokenLookup is a string in the form of "<source>:<name>" that is used
		// to extract token from the request.
		// Optional. Default value "header:Authorization".
		// Possible values:
		// - "header:<name>"
		// - "query:<name>"
		// - "cookie:<name>"
		// - "param:<name>"
		TokenLookup: "header: Authorization, query: token, cookie: jwt",
		// TokenLookup: "query:token",
		// TokenLookup: "cookie:token",

		// TokenHeaderName is a string in the header. Default value is "Bearer"
		TokenHeaderName: "Bearer",
		Identity:        reflect.TypeOf(User{}),
	})
	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	service := &Service{auth}

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(service.CheckAuth("/login"))
	{
		r.POST("/login", service.Login)
		r.GET("/hello", helloHandler)
	}
	if err = http.ListenAndServe(":8000", r); err != nil {
		log.Fatal(err)
	}
}

type Service struct {
	auth *jwt.Auth
}

func (sf *Service) Login(c *gin.Context) {
	var req login
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, nil)
		return
	}
	username := req.Username
	password := req.Password

	if (username == "admin" && password == "admin") ||
		(username == "test" && password == "test") {
		t, tm, err := sf.auth.Encode(&User{rand.Int63(), username})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": t, "tm": tm})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"msg": "账号或密码错"})
}

func checkPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func (sf *Service) CheckAuth(excludePrefixes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !checkPrefix(c.Request.URL.Path, excludePrefixes...) {
			tk, err := sf.auth.GetToken(c)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": err.Error()})
				return
			}
			identity, err := sf.auth.Decode(tk)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": err.Error()})
				return
			}
			u := identity.(*User)
			c.Set(identityKey, u)
		}
		c.Next()
	}
}

func helloHandler(c *gin.Context) {
	user, _ := c.Get(identityKey)
	u := user.(*User)
	c.JSON(http.StatusOK, gin.H{
		"uid":      u.Uid,
		"username": user.(*User).Username,
		"text":     "Hello World.",
	})
}