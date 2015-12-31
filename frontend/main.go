package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

const (
	rastechRoot = "/github.com/rastech"

	// Host is environment variable key for the http host
	Host = "HOST"
	// TLSHost is the environment variable name for the https host
	TLSHost = "HOST"

	certPath = "/ssl/godoc.crt"
	keyPath  = "/ssl/godoc.key"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, rastechRoot) {
			log.Println("proxying to our server")
			ourProxy.ServeHTTP(w, r)
		} else {
			log.Println("proxying to godoc.org")
			gddoProxy.ServeHTTP(w, r)
		}
	})

	log.Println("listening on", os.Getenv(Host))
	go log.Fatal(http.ListenAndServe(os.Getenv(Host), nil))

	log.Println("listening for tls on", os.Getenv(TLSHost))
	log.Fatal(http.ListenAndServeTLS(os.Getenv(TLSHost), certPath, keyPath, nil))
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
