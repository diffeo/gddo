# Internal godoc

This project provides access to documentation for our internal Go code. Access will be granted just to members of our company through the Google Identity Toolkit. It is deployed on Google Container Engine with two nodes. The frontend node, a server written in Go, provides an authenticated proxy to a backend node, which is just a mirror of the official golang [gddo](https://github.com/golang/gddo) repo with custom config to allow access to our github repositories. For requests outside of our domain, the frontend acts as a simple proxy to the official [godoc.org](https://www.godoc.org).

Inspired by the following discussion: https://groups.google.com/forum/#!topic/golang-nuts/dAE7iqGEfm0

test-2
