package main

import (
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/gorilla/securecookie"
	"github.com/unrolled/secure"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// reference:
// https://developers.google.com/identity/protocols/OpenIDConnect
// https://developers.google.com/identity/work/it-apps
// https://developers.google.com/identity/sign-in/web/backend-auth

const (
	rastechRoot   = "/github.com/rastech"
	rastechDomain = "rastechsoftware.com"

	defaultDomain = "godoc.rastechsoftware.com"

	googleDiscoveryDocURL = "https://accounts.google.com/.well-known/openid-configuration"

	// Host is environment variable key for the http host
	Host = "HOST"
	// TLSHost is the environment variable name for the https host
	TLSHost = "TLS_HOST"

	certPath = "/ssl/rastechsoftware.crt"
	keyPath  = "/ssl/rastechsoftware.key"

	clientIDPath     = "/oauth/clientid"
	clientSecretPath = "/oauth/clientsecret"
)

var (
	clientID = func() string {
		raw, err := ioutil.ReadFile(clientIDPath)
		if err != nil {
			panic("error reading in client id: " + err.Error())
		}
		return strings.TrimSpace(string(raw))
	}()

	clientSecret = func() string {
		raw, err := ioutil.ReadFile(clientSecretPath)
		if err != nil {
			panic("error reading in client secret: " + err.Error())
		}
		return strings.TrimSpace(string(raw))
	}()

	certs = &gitkit.Certificates{URL: "https://www.googleapis.com/oauth2/v1/certs"}

	// valid issuers for oauth tokens
	issuers = []string{"https://accounts.google.com", "accounts.google.com"}

	baseConfig oauth2.Config

	store = func() *securecookie.SecureCookie {
		// piggyback off of client secret to secure the cookies
		hashKey := sha256.Sum256([]byte(clientSecret))
		s := securecookie.New(hashKey[:], nil)
		// no longer than a 5 minute age is allowed
		s.MaxAge(60 * 5)
		return s
	}()

	secureMiddleware = secure.New(secure.Options{
		AllowedHosts: []string{
			"godoc.rastechsoftware.com",
			"godoc.meta.sc",
		},
		// redirect to SSL
		SSLRedirect: true,
		// HTTP Strict transport security
		STSSeconds: 15552000, // 6 months
		// vulnerability patches
		BrowserXssFilter:   true,
		FrameDeny:          true,
		ContentTypeNosniff: true,
		// turn off ssl and host restrictions for dev
		IsDevelopment: func() bool { return os.Getenv("DEV") != "" }(),
	})
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

	// use a fully qualified domain name set in the environment if present, otherwise fall back on the default
	domain := os.Getenv("FQDN")
	if domain == "" {
		domain = defaultDomain
	}

	baseConfig = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid profile email"},
		RedirectURL:  "https://" + domain + "/oauth-callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  info.AuthEndpoint,
			TokenURL: info.TokenEndpoint,
		},
	}
}

func main() {
	discoverEndpoints()

	http.HandleFunc("/authenticate", std(handleAuthenticate))
	http.HandleFunc("/oauth-callback", std(handleOAuthCallback))
	http.HandleFunc("/", std(auth(handleProxy)))

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

// wrapper middleware

func std(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("starting %s request to %s", r.Method, r.URL.Path)

		secureMiddleware.Handler(handler).ServeHTTP(w, r)

		log.Printf("completed %s request to %s in %v", r.Method, r.URL.Path, time.Now().Sub(start))
	}
}

func auth(handler http.HandlerFunc) http.HandlerFunc {
	redirectToAuth := func(w http.ResponseWriter, r *http.Request, failure string) {
		loc := url.URL{
			Path: "/authenticate",
		}

		queryParams := url.Values{"redirect_to": {r.URL.Path}}
		if failure != "" {
			queryParams.Add("failure", failure)
		}
		loc.RawQuery = queryParams.Encode()

		http.Redirect(w, r, loc.String(), http.StatusSeeOther)
	}

	return func(w http.ResponseWriter, r *http.Request) {

		// check authentication
		ck, err := r.Cookie(gitkit.DefaultCookieName)
		if err != nil {
			log.Println("initiating authenticate after invalid token cookie:", err)

			// no message necessary here, this is the standard case
			redirectToAuth(w, r, "")
			return
		}

		certs.LoadIfNecessary(http.DefaultTransport)
		tok, err := gitkit.VerifyToken(ck.Value, []string{clientID}, issuers, certs)
		if err != nil {
			log.Println("initiating authenticate after invalid token:", err)

			redirectToAuth(w, r, "The current token was invalid")
			return
		}

		// TODO: replace this with a check of the `hd` claim pending the resolution of
		// this issue: https://github.com/google/identity-toolkit-go-client/issues/26
		if !strings.HasSuffix(tok.Email, rastechDomain) {
			log.Println("user with unauthorized email attempted to access rastech content:", tok.EmailVerified, tok.Email)

			http.SetCookie(w, &http.Cookie{
				Name:   gitkit.DefaultCookieName,
				MaxAge: -1, // clear the cookie
			})
			redirectToAuth(w, r, "The domain for the currently authenticated user was invalid")
		}

		handler(w, r)
	}
}

// handlers

type stateInfo struct {
	Nonce      []byte
	RedirectTo string
}

func handleAuthenticate(w http.ResponseWriter, r *http.Request) {
	// initiate the oauth flow when the form is submitted
	if r.Method == "POST" {
		stateBytes := make([]byte, 40)
		_, err := io.ReadFull(rand.Reader, stateBytes)
		if err != nil {
			log.Println("error creating random state:", err)
			http.Error(w, "error creating random state", http.StatusInternalServerError)
			return
		}

		state, err := store.Encode("state", &stateInfo{
			Nonce:      stateBytes,
			RedirectTo: r.URL.Query().Get("redirect_to"),
		})
		if err != nil {
			log.Println("error encoding state:", err)
			http.Error(w, "error encoding random state", http.StatusInternalServerError)
			return
		}

		oauthURL := baseConfig.AuthCodeURL(state, oauth2.SetAuthURLParam("hd", "rastechsoftware.com"))

		http.Redirect(w, r, oauthURL, http.StatusSeeOther)
		return
	}

	data := struct {
		JustFailed     bool
		FailureMessage string
	}{}

	if msg := r.URL.Query().Get("failure"); msg != "" {
		data.JustFailed = true
		data.FailureMessage = msg
	}

	templates.Execute(w, data)
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	var state stateInfo
	if err := store.Decode("state", r.FormValue("state"), &state); err != nil {
		log.Println("invalid state:", err)
		http.Error(w, "invalid request state", http.StatusInternalServerError)
		return
	}

	oauthToken, err := baseConfig.Exchange(ctx, r.FormValue("code"))
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

	if state.RedirectTo == "" {
		state.RedirectTo = "/"
	}

	http.Redirect(w, r, state.RedirectTo, http.StatusSeeOther)
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	// for the root or anything belonging to us, proxy to our server
	if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, rastechRoot) {
		log.Println("proxying to our server")
		ourProxy.ServeHTTP(w, r)
		return
	}

	log.Println("proxying to godoc.org")
	gddoProxy.ServeHTTP(w, r)
}

// proxies to upstream gddo servers
var (
	ourProxy = httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host: func() string {
			if h := os.Getenv("GDDO_HOST"); h != "" {
				return h
			}
			return "gddo"
		}(),
	})

	gddoProxy = httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "https",
		Host:   "godoc.org",
	})
)
