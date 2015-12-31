package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/identity-toolkit-go-client/gitkit"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// see: https://developers.google.com/identity/protocols/OpenIDConnect#hd-param

const (
	rastechRoot   = "/github.com/rastech"
	rastechDomain = "rastechsoftware.com"

	googleDiscoveryDocURL = "https://accounts.google.com/.well-known/openid-configuration"

	// Host is environment variable key for the http host
	Host = "HOST"
	// TLSHost is the environment variable name for the https host
	TLSHost = "TLS_HOST"

	certPath = "/ssl/godoc.crt"
	keyPath  = "/ssl/godoc.key"
)

var (
	clientID = func() string {
		raw, err := ioutil.ReadFile("/oauth/clientid")
		if err != nil {
			panic("error reading in client id: " + err.Error())
		}
		return strings.TrimSpace(string(raw))
	}()

	clientSecret = func() string {
		raw, err := ioutil.ReadFile("/oauth/clientsecret")
		if err != nil {
			panic("error reading in client secret: " + err.Error())
		}
		return strings.TrimSpace(string(raw))
	}()

	certs = &gitkit.Certificates{URL: "https://www.googleapis.com/oauth2/v1/certs"}

	// valid issuers for oauth tokens
	issuers = []string{"https://accounts.google.com", "accounts.google.com"}

	config oauth2.Config
)

func discoverEndpoints() {
	// retrieve discovery documentation

	resp, err := http.Get(googleDiscoveryDocURL)
	if err != nil {
		log.Fatal(err)
	}

	var info struct {
		AuthEndpoint  string `json:"authorization_endpoint"`
		TokenEndpoint string `json:"token_endpoint"`
		// these keys are in json format rather than PEM
		JWKsURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		log.Fatal(err)
	}

	config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid profile email"},
		RedirectURL:  "https://meta-godoc.ngrok.io/oauth-callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  info.AuthEndpoint,
			TokenURL: info.TokenEndpoint,
		},
	}
}

func main() {
	discoverEndpoints()

	http.HandleFunc("/oauth-callback", wrap(handleOAuthCallback))
	http.HandleFunc("/", wrap(handleProxy))

	go func() {
		log.Println("listening for tls on", os.Getenv(TLSHost))
		if err := http.ListenAndServeTLS(os.Getenv(TLSHost), certPath, keyPath, nil); err != nil {
			log.Fatal(err)
		}
	}()

	log.Println("listening on", os.Getenv(Host))
	if err := http.ListenAndServe(os.Getenv(Host), nil); err != nil {
		log.Fatal(err)
	}
}

func wrap(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("starting %s request to %s", r.Method, r.URL.Path)
		handler(w, r)
		log.Printf("completed %s request to %s in %v", r.Method, r.URL.Path, time.Now().Sub(start))
	}
}

func initiateOAuthFlow(w http.ResponseWriter, r *http.Request) {
	stateBytes := make([]byte, 40)
	_, err := io.ReadFull(rand.Reader, stateBytes)
	if err != nil {
		log.Println("error creating state:", err)
		http.Error(w, "error creating random state", http.StatusInternalServerError)
		return
	}
	state := base64.URLEncoding.EncodeToString(stateBytes)

	oauthURL := config.AuthCodeURL(state, oauth2.SetAuthURLParam("hd", "rastechsoftware.com"))

	http.Redirect(w, r, oauthURL, http.StatusSeeOther)
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	state := r.FormValue("state")
	_ = state

	oauthToken, err := config.Exchange(ctx, r.FormValue("code"))
	if err != nil {
		log.Println("error exchanging code:", err)
		http.Error(w, "error exchanging code", http.StatusInternalServerError)
		return
	}

	idToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		log.Println("no id token present")
		http.Error(w, "error retrieving token", http.StatusInternalServerError)
		return
	}

	certs.LoadIfNecessary(http.DefaultTransport)
	if _, err := gitkit.VerifyToken(idToken, []string{clientID}, issuers, certs); err != nil {
		log.Println("error validating token:", err)
		http.Error(w, "error validating token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:   gitkit.DefaultCookieName,
		Value:  idToken,
		MaxAge: 60 * 60 * 24 * 7, // 1 week
	})

	redirect, ok := oauthToken.Extra("redirect_uri").(string)
	if !ok {
		redirect = "/"
	}

	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	// for anything belonging to us, ensure we are authenticated
	if strings.HasPrefix(r.URL.Path, rastechRoot) {

		ck, err := r.Cookie(gitkit.DefaultCookieName)
		if err != nil {
			log.Println("initiating login after invalid token cookie:", err)

			initiateOAuthFlow(w, r)
			return
		}

		certs.LoadIfNecessary(http.DefaultTransport)
		tok, err := gitkit.VerifyToken(ck.Value, []string{clientID}, issuers, certs)
		if err != nil {
			log.Println("initiating login after invalid token:", err)

			initiateOAuthFlow(w, r)
			return
		}
		if !strings.HasSuffix(tok.Email, rastechDomain) {
			log.Println("user with unauthorized email attempted to access rastech content:", tok.EmailVerified, tok.Email)
			http.Error(w, "only users with rastechsoftware.com email addresses may access this content", http.StatusForbidden)
			return
		}

		log.Println("proxying to our server")
		ourProxy.ServeHTTP(w, r)
		return
	}

	log.Println("proxying to godoc.org")
	gddoProxy.ServeHTTP(w, r)
}

var (
	ourProxy = httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   "gddo",
	})

	gddoProxy = httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "https",
		Host:   "godoc.org",
	})
)
