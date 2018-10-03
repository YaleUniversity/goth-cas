package cas

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/markbates/goth"
)

// Session stores data during the cas auth process.
type Session struct {
	AuthURL string
	User    *goth.User
}

// AuthenticationSuccess is the success response from CAS
type AuthenticationSuccess struct {
	XMLName xml.Name `xml:"authenticationSuccess,omitempty"`
	User    CasUser  `xml:"http://www.yale.edu/tp/cas user,omitempty"`
}

// AuthenticationFailure is the failure response from CAS
type AuthenticationFailure struct {
	XMLName xml.Name `xml:"authenticationFailure,omitempty"`
	Code    string   `xml:"code,attr"`
	Reason  string   `xml:",chardata"`
}

// ServiceResponse is the success or failure response from CAS
type ServiceResponse struct {
	XMLName               xml.Name               `xml:"serviceResponse,omitempty"`
	AttrXmlnscas          string                 `xml:"xmlns cas,attr"`
	AuthenticationSuccess *AuthenticationSuccess `xml:"http://www.yale.edu/tp/cas authenticationSuccess,omitempty"`
	AuthenticationFailure *AuthenticationFailure `xml:"http://www.yale.edu/tp/cas authenticationFailure,omitempty"`
}

// CasUser is the cas user attribute in the XML response
type CasUser struct {
	XMLName xml.Name `xml:"user,omitempty"`
	ID      string   `xml:",chardata"`
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the CAS provider.
func (s *Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize validates the session with CAS and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	ticket := params.Get("ticket")
	url := ValidateURL + "?service=" + url.QueryEscape(p.CallbackURL) + "&ticket=" + ticket

	resp, err := goth.HTTPClientWithFallBack(p.Client()).Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	casResponse := ServiceResponse{}
	err = xml.Unmarshal(body, &casResponse)
	if err != nil {
		return "", err
	}

	if casResponse.AuthenticationSuccess != nil {
		s.User = &goth.User{
			UserID: casResponse.AuthenticationSuccess.User.ID,
		}
	} else if casResponse.AuthenticationFailure != nil {
		code := casResponse.AuthenticationFailure.Code
		return "", errors.New(code)
	}

	return ticket, nil
}

// Marshal the session into a string
func (s *Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

// String returns the session as a string
func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}
