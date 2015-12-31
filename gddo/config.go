package main

import (
	"io/ioutil"
	"strings"

	"net/http"
)

type tokenRT struct {
	t http.RoundTripper
}

func (t tokenRT) RoundTrip(req *http.Request) (*http.Response, error) {
	// Create a new OAuth access token at https://github.com/settings/tokens/new and enter it here.
	if req.URL.Host == "api.github.com" && req.URL.Scheme == "https" {
		req.SetBasicAuth(githubToken, "x-oauth-basic")
	}
	return t.t.RoundTrip(req)
}

var githubToken string

func init() {
	httpClient.Transport = tokenRT{httpClient.Transport}

	token, err := ioutil.ReadFile("/github/token")
	if err != nil {
		panic("error reading in github token:" + err.Error())
	}
	githubToken = strings.TrimSpace(string(token))
}
