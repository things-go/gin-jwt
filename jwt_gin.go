package jwt

// Config auth config
type Config struct {
	SignConfig

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional, Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "cookie:<name>"
	TokenLookup string
	// TokenHeaderName is a string in the header.
	// Possible value is "Bearer"
	TokenHeaderName string
}

// Auth provides a Json-Web-Token authentication implementation.
// The token then needs to be passed in the Authentication header.
// Example: Authorization:Bearer XXX_TOKEN_XXX
type Auth struct {
	*Signature
	*Lookup
}

// New for check error with Config
func New(c Config) (*Auth, error) {
	sign, err := NewSignature(c.SignConfig)
	if err != nil {
		return nil, err
	}
	return &Auth{
		Signature: sign,
		Lookup:    NewLookup(c.TokenLookup, c.TokenHeaderName),
	}, nil
}
