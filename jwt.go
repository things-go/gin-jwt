package jwt

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"reflect"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Claims Structured version of Claims Section, as referenced at
// https://tools.ietf.org/html/rfc7519#section-4.1
// See examples for how to use this with your own claim types
type Claims struct {
	jwt.RegisteredClaims
	Identity interface{} `json:"identity"`
}

// SignConfig Signature config
type SignConfig struct {
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

	// Identity type for jwt used, which you want to encode into jwt payload
	// Required
	Identity interface{}
}

// Signature provides a Json-Web-Token authentication implementation.
type Signature struct {
	timeout       time.Duration
	maxRefresh    time.Duration
	signingMethod jwt.SigningMethod
	encodeKey     interface{}
	decodeKey     interface{}
	identity      interface{}
}

// NewSignature new signature with Config
func NewSignature(c SignConfig) (*Signature, error) {
	var err error

	if c.Identity == nil {
		return nil, ErrMissingIdentity
	}
	if c.Timeout == 0 {
		c.Timeout = time.Hour
	}

	mw := &Signature{
		timeout:    c.Timeout,
		maxRefresh: c.MaxRefresh,
		identity:   reflect.New(reflect.Indirect(reflect.ValueOf(c.Identity)).Type()).Interface(),
	}

	usingPublicKeyAlgo := false
	switch c.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		usingPublicKeyAlgo = true
		mw.encodeKey, err = readPrivateKey(c.PrivKeyFile)
		if err != nil {
			return nil, err
		}
		mw.decodeKey, err = readPublicKey(c.PubKeyFile)
		if err != nil {
			return nil, err
		}
	case "HS256", "HS512", "HS384":
	default:
		c.SigningAlgorithm = "HS256"
	}
	mw.signingMethod = jwt.GetSigningMethod(c.SigningAlgorithm)

	if !usingPublicKeyAlgo {
		if c.Key == nil {
			return nil, ErrMissingSecretKey
		}
		mw.encodeKey = c.Key
		mw.decodeKey = c.Key
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

// Encode identity in to token
// if timeouts not give ,use default timeout
func (sf *Signature) Encode(identity interface{}, timeouts ...time.Duration) (string, time.Time, error) {
	timeout := sf.timeout
	if len(timeouts) > 0 && timeouts[0] > 0 {
		timeout = timeouts[0]
	}
	expire := time.Now().Add(timeout)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expire),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
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

// Decode decode token to identity
func (sf *Signature) Decode(token string) (interface{}, error) {
	return sf.CheckTokenExpire(sf.DecodeToken(token))
}

// DecodeToken parse jwt token string
func (sf *Signature) DecodeToken(token string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(token,
		&Claims{Identity: sf.identity},
		func(t *jwt.Token) (interface{}, error) {
			if sf.signingMethod != t.Method {
				return nil, ErrInvalidSigningAlgorithm
			}
			return sf.decodeKey, nil
		},
	)
}

// CheckTokenExpire check token expire or not, and return identity value
func (sf *Signature) CheckTokenExpire(token *jwt.Token, err error) (interface{}, error) {
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
	if claims.VerifyExpiresAt(time.Now().Add(-sf.maxRefresh), true) {
		return claims.Identity, nil
	}
	return nil, ErrExpiredToken
}
