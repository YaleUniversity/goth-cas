package cas

import (
	"testing"

	"github.com/markbates/goth"
)

func TestName(t *testing.T) {
	c := New("http://localhost/auth/cas/callback")
	if n := c.Name(); n != "cas" {
		t.Errorf("expected cas, got %s", n)
	}
}

func TestSetName(t *testing.T) {
	c := New("http://localhost/auth/cas/callback")
	c.SetName("juliaIsBetter")
	if n := c.Name(); n != "juliaIsBetter" {
		t.Errorf("expected juliaIsBetter, got %s", n)
	}
}

func TestBeginAuth(t *testing.T) {
	LoginURL = "https://128bitfloats.example.edu/cas/login"
	ValidateURL = "https://128bitfloats.example.edu/cas/serviceValidate"
	c := New("http://localhost/auth/cas/callback")
	s, err := c.BeginAuth("xyz")
	if err != nil {
		t.Errorf("expected no error, got %s", err)
	}

	expected := "https://128bitfloats.example.edu/cas/login?service=http%3A%2F%2Flocalhost%2Fauth%2Fcas%2Fcallback"
	if s.(*Session).AuthURL != expected {
		t.Errorf("Expected %s got %s", expected, s.(*Session).AuthURL)
	}
}

func TestRefreshToken(t *testing.T) {
	c := New("http://localhost/auth/cas/callback")
	token, err := c.RefreshToken("")
	if err == nil || token != nil {
		t.Errorf("Expected RefreshToken to return an error")
	}
}

func TestRefreshTokenAvailable(t *testing.T) {
	c := New("http://localhost/auth/cas/callback")
	token := c.RefreshTokenAvailable()
	if token != false {
		t.Errorf("Expected RefreshTokenAvailable to return an false")
	}
}

func TestFetchUser(t *testing.T) {
	c := New("http://localhost/auth/cas/callback")
	_, err := c.FetchUser(&Session{})
	if err == nil {
		t.Errorf("expected error for nil user in session")
	}

	u, err := c.FetchUser(&Session{User: &goth.User{UserID: "foobar"}})
	if err != nil {
		t.Errorf("got error from fetchUser: %s", err)
	}

	if u.UserID != "foobar" {
		t.Errorf("expected userid to be foobar, got %s", u.UserID)
	}
}
