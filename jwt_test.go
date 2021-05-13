package jwt

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Identity struct {
	UID      int64
	Username string
}

var key = []byte("secret key")

func TestMissingKey(t *testing.T) {
	_, err := New(Config{
		Identity: reflect.TypeOf(Identity{}),
	})
	assert.Error(t, err)
	assert.Equal(t, ErrMissingSecretKey, err)
}

func TestMissingPrivKey(t *testing.T) {
	_, err := New(Config{
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "nonexisting",
		Identity:         reflect.TypeOf(Identity{}),
	})
	assert.Error(t, err)
	assert.Equal(t, ErrNoPrivKeyFile, err)
}

func TestMissingPubKey(t *testing.T) {
	_, err := New(Config{
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyFile:       "nonexisting",
		Identity:         reflect.TypeOf(Identity{}),
	})
	assert.Error(t, err)
	assert.Equal(t, ErrNoPubKeyFile, err)
}

func TestInvalidPrivKey(t *testing.T) {
	_, err := New(Config{
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/invalidprivkey.key",
		PubKeyFile:       "testdata/jwtRS256.key.pub",
		Identity:         reflect.TypeOf(Identity{}),
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPrivKey, err)
}

func TestInvalidPubKey(t *testing.T) {
	_, err := New(Config{
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyFile:       "testdata/invalidpubkey.key",
		Identity:         reflect.TypeOf(Identity{}),
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPubKey, err)
}

func TestMissIdentity(t *testing.T) {
	_, err := New(Config{
		Key: key,
	})

	assert.Error(t, err)
	assert.Equal(t, ErrMissingIdentity, err)
}

func TestAuth(t *testing.T) {
	auth, err := New(Config{Key: key, Identity: Identity{}})
	assert.NoError(t, err)

	want := &Identity{1, "username"}

	token, _, err := auth.Encode(want)
	require.NoError(t, err)

	v, err := auth.Decode(token)
	require.NoError(t, err)

	got, ok := v.(*Identity)
	require.True(t, ok)

	require.Equal(t, want, got)
}

// const identityKey = "identify"

// type Login struct {
// 	Username string `form:"username" json:"username" binding:"required"`
// 	Password string `form:"password" json:"password" binding:"required"`
// }

//
// type server struct {
// 	auth *Auth
// }
//
// func (sf *server) Login(c *gin.Context) {
// 	var loginVals Login
//
// 	if err := c.ShouldBind(&loginVals); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
// 		return
// 	}
//
// 	usename := loginVals.Username
// 	password := loginVals.Password
// 	if usename == "admin" && password == "admin" {
// 		token, expire, err := sf.auth.Encode(&Identity{rand.Int63(), usename})
// 		if err != nil {
// 			c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
// 			return
// 		}
// 		c.JSON(http.StatusOK, gin.H{"token": token, "expire": expire})
// 		return
// 	}
// 	c.JSON(http.StatusBadRequest, gin.H{"msg": "incorrect username or password"})
// }
//
// func (sf *server) CheckAuth(c *gin.Context) {
// 	tk, err := sf.auth.GetToken(c)
// 	if err != nil {
// 		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": err.Error()})
// 		return
// 	}
// 	identity, err := sf.auth.Decode(tk)
// 	if err != nil {
// 		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": err.Error()})
// 		return
// 	}
// 	u := identity.(*Identity)
// 	c.Set(identityKey, u)
// 	c.Next()
// }
//
//
