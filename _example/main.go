package main

import (
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"

	ginjwt "github.com/things-go/gin-jwt"
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

type Claims struct {
	jwt.RegisteredClaims
	Identity User `json:"identity"`
}

func main() {
	// jwt auth
	auth, err := ginjwt.New(ginjwt.Config{
		SignConfig: ginjwt.SignConfig{
			Algorithm: "HS256",
			Key:       []byte("secret key"),
		},

		// NewLookup new lookup
		// lookup is a string in the form of "<source>:<name>[:<headerName>]" that is used
		// to extract token from the request.
		// use like "header:<name>[:<headerName>],query:<name>,cookie:<name>,param:<name>"
		// Optional, Default value "header:Authorization:Bearer".
		// Possible values:
		// - "header:<name>:<headerName>", <headerName> is a special string in the header, Possible value is "Bearer"
		// - "query:<name>"
		// - "cookie:<name>"
		// - "param:<name>"
		TokenLookup: "header:Authorization:Bearer,query:token,cookie:jwt",
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
	auth *ginjwt.Auth
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
		uid := rand.Int63()

		expiredAt := time.Now().Add(time.Hour)
		t, err := sf.auth.NewWithClaims(Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expiredAt),
			},
			Identity: User{uid, username},
		})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
			return
		}
		log.Printf("uid: %d, token: %s", uid, t)
		c.JSON(http.StatusOK, gin.H{"token": t, "tm": expiredAt})
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
			tk, err := sf.auth.Get(c.Request)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": err.Error()})
				return
			}
			v, err := sf.auth.ParseWithClaims(tk, &Claims{})
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": err.Error()})
				return
			}
			u := v.Claims.(*Claims)
			c.Set(identityKey, &u.Identity)
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
