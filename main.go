package godoc

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/urlfetch"
)

var gddoURL = &url.URL{
	Scheme: "https",
	Host:   "godoc.org",
}

func gddoProxy(ctx context.Context) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(gddoURL)
	proxy.Transport = urlfetch.Client(ctx).Transport
	return proxy
}

func init() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := appengine.NewContext(r)
		proxy := gddoProxy(ctx)

		proxy.ServeHTTP(w, r)
	})
}
