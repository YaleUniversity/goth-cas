package cas

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type TestParams struct {
	Ticket string
}

func (t TestParams) Get(string) string {
	return t.Ticket
}

var successResponse = `
<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
    <cas:authenticationSuccess>
        <cas:user>nemo</cas:user>
    </cas:authenticationSuccess>
</cas:serviceResponse>
`

var failureResponse = `
<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
	<cas:authenticationFailure code='INVALID_TICKET'>
		ticket &#039;porgy&#039; not recognized
	</cas:authenticationFailure>
</cas:serviceResponse>
`

func TestAuthorize(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("http request %+v", *r)
		w.Header().Set("Content-Type", "application/json")
		uri, err := url.ParseRequestURI(r.RequestURI)
		if err != nil {
			t.Error(err)
		}
		t.Logf("parsed request uri %+v", *uri)

		switch {
		case uri.Path == "/cas/login":
			t.Log("cas login")
		case uri.Path == "/cas/serviceValidate":
			t.Log("cas service validate")
			cbk, ok := uri.Query()["service"]
			if !ok {
				t.Errorf("expected service query parameter for validate")
			}

			serviceURL, err := url.ParseRequestURI(cbk[0])
			if err != nil {
				t.Error(err)
			}

			if serviceURL.Path != "/auth/cas/callback" {
				t.Errorf("expected '/auth/cas/callback', got %s", serviceURL.Path)
			}

			tgt, ok := uri.Query()["ticket"]
			if !ok {
				t.Errorf("expected ticket query param 'porgy' for validate")
			}

			if tgt[0] == "porgy" {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, successResponse)
			} else if tgt[0] == "bluefish" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintln(w, failureResponse)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
		case uri.Path == "/auth/cas/callback":
			t.Log("cas auth callback")
		default:
			t.Error("unknown uri", uri)
		}
	}))
	defer ts.Close()

	LoginURL = ts.URL + "/cas/login"
	ValidateURL = ts.URL + "/cas/serviceValidate"
	provider := New(ts.URL + "/auth/cas/callback")
	session, err := provider.BeginAuth("foobar")
	if err != nil {
		t.Error(err)
	}
	t.Logf("Built new session (%+v) and provider (%+v)", session, provider)

	ticket, err := session.Authorize(provider, TestParams{Ticket: "porgy"})
	if err != nil {
		t.Error(err)
	}
	t.Logf("got success ticket response '%s'", ticket)
	user, err := provider.FetchUser(session)
	if err != nil {
		t.Error(err)
	}

	if user.UserID != "nemo" {
		t.Error("expected userid 'nemo', got", user.UserID)
	}

	ticket, err = session.Authorize(provider, TestParams{Ticket: "bluefish"})
	if err == nil {
		t.Error("expected error for Authorize failure, got nil")
	}
	t.Logf("got failure ticket response '%s'", ticket)
}
