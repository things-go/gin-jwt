package jwt

// Config auth config
type Config struct {
	SignConfig

	// TokenLookup is a string in the form of "<source>:<name>[:<headerName>]" that is used
	// to extract token from the request.
	// use like "header:<name>[:<headerName>],query:<name>,cookie:<name>,param:<name>"
	// Optional, Default value "header:Authorization:Bearer".
	// Possible values:
	// - "header:<name>:<headerName>", <headerName> is a special string in the header, Possible value is "Bearer"
	// - "query:<name>"
	// - "cookie:<name>"
	// - "param:<name>"
	TokenLookup string
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
		Lookup:    NewLookup(c.TokenLookup),
	}, nil
}
