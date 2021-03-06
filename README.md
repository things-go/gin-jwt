# JWT useful for Gin Framework

[![GoDoc](https://godoc.org/github.com/things-go/gin-jwt?status.svg)](https://godoc.org/github.com/things-go/gin-jwt)
[![Go.Dev reference](https://img.shields.io/badge/go.dev-reference-blue?logo=go&logoColor=white)](https://pkg.go.dev/github.com/things-go/gin-jwt?tab=doc)
[![codecov](https://codecov.io/gh/things-go/gin-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/things-go/gin-jwt)
![Action Status](https://github.com/things-go/gin-jwt/workflows/Go/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/things-go/gin-jwt)](https://goreportcard.com/report/github.com/things-go/gin-jwt)
[![Licence](https://img.shields.io/github/license/things-go/gin-jwt)](https://raw.githubusercontent.com/things-go/gin-jwt/master/LICENSE)
[![Tag](https://img.shields.io/github/v/tag/things-go/gin-jwt)](https://github.com/thinkgos/gin-jwt/tags)


This is a jwt useful for [Gin](https://github.com/gin-gonic/gin) framework.

It uses [jwt-go](https://github.com/dgrijalva/jwt-go) to provide a jwt encode and decode token.

## Usage

Download and install using [go module](https://blog.golang.org/using-go-modules):

```sh
export GO111MODULE=on
go get github.com/things-go/gin-jwt
```

Import it in your code:

```go
import "github.com/things-go/gin-jwt"
```

Download and install without using [go module](https://blog.golang.org/using-go-modules):

```sh
go get github.com/things-go/gin-jwt
```

Import it in your code:

```go
import "github.com/things-go/gin-jwt"
```

## Example

Please see [the example file](_example/main.go).

[embedmd]:# (_example/main.go go)
```go
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
		// lookup is a string in the form of "<source>:<name>[:<prefix>]" that is used
		// to extract token from the request.
		// use like "header:<name>[:<prefix>],query:<name>,cookie:<name>,param:<name>"
		// Optional, Default value "header:Authorization:Bearer".
		// Possible values:
		// - "header:<name>:<prefix>", <prefix> is a special string in the header, Possible value is "Bearer"
		// - "query:<name>"
		// - "cookie:<name>"
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
	c.JSON(http.StatusBadRequest, gin.H{"msg": "??????????????????"})
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
```

## Demo

Please run _example/main.go file and listen `8000` port.

```sh
go run _example/main.go
```
