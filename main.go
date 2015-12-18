package godoc

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"
)

func init() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/github.com/rastech") {
			handleOurs(w, r)
		} else {
			handleUpstream(w, r)
		}
	})
}

// handle requests ourselves

func handleOurs(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Coming soon: our private repositories!"))
}

// proxy requests to godoc.org

var gddoURL = &url.URL{
	Scheme: "https",
	Host:   "godoc.org",
}

func handleUpstream(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)

	log.Infof(ctx, "proxying to upstream")

	proxy := httputil.NewSingleHostReverseProxy(gddoURL)
	proxy.Transport = urlfetch.Client(ctx).Transport

	proxy.ServeHTTP(w, r)
}
