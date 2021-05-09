package main

import (
	"log"
	"math/rand"
	"net/http"
	"reflect"
	"time"

	"github.com/gin-gonic/gin"

	jwt "github.com/things-go/gin-jwt"
)

const identityKey = "identify"

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
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

// User demo
type User struct {
	Uid      int64
	Username string
}

func main() {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

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

	r.POST("/login", func(c *gin.Context) {
		var loginVals login
		if err := c.ShouldBind(&loginVals); err != nil {
			c.JSON(http.StatusBadRequest, nil)
			return
		}
		username := loginVals.Username
		password := loginVals.Password

		if (username == "admin" && password == "admin") ||
			(username == "test" && password == "test") {
			t, tm, err := auth.Encode(&User{rand.Int63(), username})
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"token": t, "tm": tm})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"msg": "账号或密码错"})
	})

	authGroup := r.Group("/auth").
		Use(func(c *gin.Context) {
			tk, err := auth.GetToken(c)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": err.Error()})
				return
			}
			identity, err := auth.Decode(tk)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": err.Error()})
				return
			}
			u := identity.(*User)
			c.Set(identityKey, u)
			c.Next()
		})
	{
		authGroup.GET("/hello", helloHandler)
	}

	if err := http.ListenAndServe(":8000", r); err != nil {
		log.Fatal(err)
	}
}
