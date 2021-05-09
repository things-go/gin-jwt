package jwt

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type Claims struct {
	jwt.StandardClaims
	Identity interface{} `json:"identity"`
}

type Config struct {
	// 支持签名算法: HS256, HS384, HS512, RS256, RS384 or RS512
	// Optional, Default HS256.
	SigningAlgorithm string
	// Secret key used for signing.
	// Required, HS256, HS384, HS512.
	Key []byte
	// Private key file for asymmetric algorithms,
	// Public key file for asymmetric algorithms
	// Required, RS256, RS384 or RS512.
	PrivKeyFile, PubKeyFile string

	// Duration that a jwt token is valid.
	// Optional, Defaults to one hour.
	Timeout time.Duration
	// This field allows clients to refresh their token until MaxRefresh has passed.
	// Note that clients can refresh their token in the last moment of MaxRefresh.
	// This means that the maximum validity timespan for a token is TokenTime + MaxRefresh.
	// Optional, defaults to 0 meaning not refreshable.
	MaxRefresh time.Duration

	// Identity type for jwt used
	// Required
	Identity reflect.Type

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional, Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "cookie:<name>"
	TokenLookup string
	// TokenHeaderName is a string in the header.
	// Default value is "Bearer"
	TokenHeaderName string

	// For cookie
	// Duration that a cookie is valid. Optional, by default equals to Timeout value.
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

// Auth provides a Json-Web-Token authentication implementation. On failure, a 401 HTTP response
// is returned. On success, the wrapped middleware is called, and the userID is made available as
// c.Get("userID").(string).
// Users can get a token by posting a json request to LoginHandler. The token then needs to be passed in
// the Authentication header. Example: Authorization:Bearer XXX_TOKEN_XXX
type Auth struct {
	Config

	signingMethod jwt.SigningMethod
	encodeKey     interface{}
	decodeKey     interface{}
}

var (
	// ErrMissingToken can be thrown by follow
	// if authing with a HTTP header, the Auth header needs to be set
	// if authing with URL Query, the query token variable is empty
	// if authing with a cookie, the token cookie is empty
	// if authing with parameter in path, the parameter in path is empty
	ErrMissingToken = errors.New("auth token is empty")
	// ErrInvalidAuthHeader indicates auth header is invalid
	ErrInvalidAuthHeader = errors.New("auth header is invalid")
	// ErrInvalidToken indicates token is invalid
	ErrInvalidToken = errors.New("token is invalid")
	// ErrExpiredToken indicates JWT token has expired. Can't refresh.
	ErrExpiredToken = errors.New("token is expired")
	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid,
	// needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

	// ErrNoPubKeyFile indicates that the given public key is unreadable
	ErrNoPubKeyFile = errors.New("public key file unreadable")
	// ErrInvalidPubKey indicates the the given public key is invalid
	ErrInvalidPubKey = errors.New("public key invalid")
	// ErrNoPrivKeyFile indicates that the given private key is unreadable
	ErrNoPrivKeyFile = errors.New("private key file unreadable")
	// ErrInvalidPrivKey indicates that the given private key is invalid
	ErrInvalidPrivKey = errors.New("private key invalid")
)

// New for check error with Auth
func New(c Config) (*Auth, error) {
	var err error

	mw := &Auth{Config: c}

	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:Authorization"
	}
	if mw.TokenHeaderName = strings.TrimSpace(mw.TokenHeaderName); len(mw.TokenHeaderName) == 0 {
		mw.TokenHeaderName = "Bearer"
	}

	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}

	if mw.CookieMaxAge == 0 {
		mw.CookieMaxAge = mw.Timeout
	}
	if mw.CookieName == "" {
		mw.CookieName = "jwt"
	}

	usingPublicKeyAlgo := false
	switch mw.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		usingPublicKeyAlgo = true
		mw.encodeKey, err = readPrivateKey(mw.PrivKeyFile)
		if err != nil {
			return nil, err
		}
		mw.decodeKey, err = readPublicKey(mw.PubKeyFile)
		if err != nil {
			return nil, err
		}
	case "HS256", "HS512", "HS384":
	default:
		mw.SigningAlgorithm = "HS256"
	}
	mw.signingMethod = jwt.GetSigningMethod(mw.SigningAlgorithm)

	if !usingPublicKeyAlgo {
		if mw.Key == nil {
			return nil, errors.New("secret key is required")
		}
		mw.encodeKey = mw.Key
		mw.decodeKey = mw.Key
	}
	return mw, nil
}

func readPrivateKey(privKeyFile string) (*rsa.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(privKeyFile)
	if err != nil {
		return nil, ErrNoPrivKeyFile
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return nil, ErrInvalidPrivKey
	}
	return key, nil
}

func readPublicKey(pubKeyFile string) (*rsa.PublicKey, error) {
	keyData, err := ioutil.ReadFile(pubKeyFile)
	if err != nil {
		return nil, ErrNoPubKeyFile
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return nil, ErrInvalidPubKey
	}
	return key, nil
}

func (sf *Auth) Encode(identity interface{}) (string, time.Time, error) {
	expire := time.Now().Add(sf.Timeout)
	claims := Claims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expire.Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		Identity: identity,
	}
	// Create the token
	tokenString, err := jwt.NewWithClaims(sf.signingMethod, claims).SignedString(sf.encodeKey)
	if err != nil {
		return "", expire, errors.New("create JWT Token failed")
	}
	return tokenString, expire, nil
}

func (sf *Auth) Decode(token string) (interface{}, error) {
	return sf.CheckTokenExpire(sf.DecodeToken(token))
}

// RefreshToken refresh token and check if token is expired
func (sf *Auth) RefreshToken(c *gin.Context) (string, time.Time, error) {
	token, err := sf.GetToken(c)
	if err != nil {
		return "", time.Now(), err
	}
	identity, err := sf.Decode(token)
	if err != nil {
		return "", time.Now(), err
	}
	return sf.Encode(identity)
}

// DecodeToken parse jwt token string
func (sf *Auth) DecodeToken(token string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(token,
		&Claims{Identity: reflect.New(sf.Identity).Interface()},
		func(t *jwt.Token) (interface{}, error) {
			if sf.signingMethod != t.Method {
				return nil, ErrInvalidSigningAlgorithm
			}
			return sf.decodeKey, nil
		},
	)
}

func (sf *Auth) CheckTokenExpire(token *jwt.Token, err error) (interface{}, error) {
	if err != nil {
		// If we receive an error, and the error is anything other than a single
		// ValidationErrorExpired, we want to return the error.
		// If the error is just ValidationErrorExpired, we want to continue, as we can still
		// refresh the token if it's within the MaxRefresh time.
		ve, ok := err.(*jwt.ValidationError)
		if !ok || ve.Errors != jwt.ValidationErrorExpired {
			return nil, err
		}
		return nil, ErrExpiredToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidToken
	}
	if claims.VerifyExpiresAt(time.Now().Add(-sf.MaxRefresh).Unix(), true) {
		return claims.Identity, nil
	}
	return nil, ErrExpiredToken
}

// SetCookie can be used by clients to set the jwt cookie
func (sf *Auth) SetCookie(c *gin.Context, tokenString string) {
	if sf.CookieSameSite != 0 {
		c.SetSameSite(sf.CookieSameSite)
	}
	c.SetCookie(
		sf.CookieName, tokenString, int(sf.CookieMaxAge/time.Second),
		"/", sf.CookieDomain, sf.SecureCookie, sf.CookieHTTPOnly,
	)
}

// RemoveCookie can be used by clients to remove the jwt cookie (if set)
func (sf *Auth) RemoveCookie(c *gin.Context) {
	if sf.CookieSameSite != 0 {
		c.SetSameSite(sf.CookieSameSite)
	}
	c.SetCookie(
		sf.CookieName, "", -1,
		"/", sf.CookieDomain, sf.SecureCookie, sf.CookieHTTPOnly,
	)
}

// GetToken 获取token, 从Request中获取,由 TokenLookup 定义
func (sf *Auth) GetToken(c *gin.Context) (string, error) {
	var token string
	var err error

	methods := strings.Split(sf.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token, err = jwtFromHeader(c, v, sf.TokenHeaderName)
		case "query":
			token, err = jwtFromQuery(c, v)
		case "cookie":
			token, err = jwtFromCookie(c, v)
		case "param":
			token, err = jwtFromParam(c, v)
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

func jwtFromHeader(c *gin.Context, key, headerName string) (string, error) {
	authHeader := c.Request.Header.Get(key)
	if authHeader == "" {
		return "", ErrMissingToken
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == headerName) {
		return "", ErrInvalidAuthHeader
	}
	return parts[1], nil
}

func jwtFromQuery(c *gin.Context, key string) (string, error) {
	token := c.Query(key)
	if token == "" {
		return "", ErrMissingToken
	}
	return token, nil
}

func jwtFromCookie(c *gin.Context, key string) (string, error) {
	cookie, _ := c.Cookie(key)
	if cookie == "" {
		return "", ErrMissingToken
	}
	return cookie, nil
}

func jwtFromParam(c *gin.Context, key string) (string, error) {
	token := c.Param(key)
	if token == "" {
		return "", ErrMissingToken
	}
	return token, nil
}
