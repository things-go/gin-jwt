package jwt

import (
	"crypto/rsa"
	"io/ioutil"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

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
}

// Signature provides a Json-Web-Token authentication implementation.
type Signature struct {
	timeout       time.Duration
	maxRefresh    time.Duration
	signingMethod jwt.SigningMethod
	encodeKey     interface{}
	decodeKey     interface{}
}

// NewSignature new signature with Config
func NewSignature(c SignConfig) (*Signature, error) {
	var err error

	if c.Timeout == 0 {
		c.Timeout = time.Hour
	}

	mw := &Signature{
		timeout:    c.Timeout,
		maxRefresh: c.MaxRefresh,
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

// GetTimeout return timeout time.
// Duration that a jwt token is valid.
// Optional, Defaults to one hour.
func (sf *Signature) GetTimeout() time.Duration { return sf.timeout }

// GetMaxRefresh return max refresh time
// This field allows clients to refresh their token until MaxRefresh has passed.
// Note that clients can refresh their token in the last moment of MaxRefresh.
// This means that the maximum validity timespan for a token is TokenTime + MaxRefresh.
func (sf *Signature) GetMaxRefresh() time.Duration { return sf.maxRefresh }

// NewWithClaims creates a new Token with the claims.
func (sf *Signature) NewWithClaims(claims jwt.Claims) (string, error) {
	return jwt.NewWithClaims(sf.signingMethod, claims).SignedString(sf.encodeKey)
}

// ParseWithClaims parse token string for claims
func (sf *Signature) ParseWithClaims(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString,
		claims,
		func(t *jwt.Token) (interface{}, error) {
			if sf.signingMethod != t.Method {
				return nil, ErrInvalidSigningAlgorithm
			}
			return sf.decodeKey, nil
		},
	)
}
