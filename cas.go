// Package cas implements the protocol for authenticating users through CAS.
package cas

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// These vars define the Login url and validation url for the cas server.
var (
	LoginURL    = "https://secure.its.yale.edu/cas/login"
	ValidateURL = "https://secure.its.yale.edu/cas/serviceValidate"
)

// New creates a new CAS provider. You should always call `cas.New` to get a new Provider.
func New(callbackURL string) *Provider {
	p := &Provider{
		CallbackURL:  callbackURL,
		providerName: "cas",
	}
	return p
}

// Provider is the implementation of `goth.Provider` for accessing CASified apps.
type Provider struct {
	CallbackURL  string
	HTTPClient   *http.Client
	providerName string
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client returns an http client
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the cas package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth sets up the cas session AuthURL
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	service := url.QueryEscape(p.CallbackURL)
	u, err := url.Parse(LoginURL + "?service=" + service)
	if err != nil {
		return &Session{}, err
	}
	session := &Session{
		AuthURL: u.String(),
	}
	return session, nil
}

// RefreshToken refresh token is not provided by cas
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by cas")
}

// RefreshTokenAvailable refresh token is not provided by cas
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	if s.User == nil {
		return goth.User{}, errors.New("no user information found in session")
	}
	return *s.User, nil
}
