// Copyright (c) 2016 Danilo Bürger <info@danilobuerger.de>

// Package oauth2 is a server implementation of the OAuth 2.0 Authorization Framework (https://tools.ietf.org/html/rfc6749).
package oauth2

import (
	"context"
	"net/http"
	"net/url"
)

// Log logs server errors.
type Log interface {
	Println(v ...interface{})
}

// Client is a oauth2 client:
//
// An application making protected resource requests on behalf of the
// resource owner and with its authorization. The term "client" does
// not imply any particular implementation characteristics (e.g.,
// whether the application executes on a server, a desktop, or other
// devices).
//
// https://tools.ietf.org/html/rfc6749#section-1.1
type Client interface {
	Identifier() string
	IsAllowedRedirectURI(uri string) bool
	IsAllowedGrantType(identifier string) bool
}

// Storer finds clients by their identifier.
type Storer interface {
	FindClient(ctx context.Context, id string) (Client, error)
}

// GrantType is a oauth2 grant type.
type GrantType interface {
	Identifier() string
}

// TokenGrantType is a grant type on the /token endpoint.
type TokenGrantType interface {
	GrantType
	GrantName() string
	Grant(req *http.Request, client Client) (*AccessResponse, error)
}

// AuthorizeGrantType is a grant type on the /authorize endpoint.
type AuthorizeGrantType interface {
	GrantType
	ResponseName() string
	Respond(w http.ResponseWriter, req *http.Request, client Client, authReq *AuthorizeRequest)
}

// AuthorizeRequest is a request on the /authorize endpoint.
type AuthorizeRequest struct {
	URL          *url.URL
	ResponseType string
	ClientID     string
	RedirectURI  string
	State        string
}

// AccessResponse holds a valid and authorized access response.
type AccessResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    string
	RefreshToken string
	Info         map[string]interface{}
}
