// Copyright (c) 2016 Danilo Bürger <info@danilobuerger.de>

package oauth2

import (
	"net/http"
	"net/url"
)

// ImplicitGrantType is used to obtain access tokens (it does not
// support the issuance of refresh tokens) and is optimized for public
// clients known to operate a particular redirection URI.  These clients
// are typically implemented in a browser using a scripting language
// such as JavaScript.
//
// https://tools.ietf.org/html/rfc6749#section-4.2
const ImplicitGrantType = "implicit"

// ImplicitGrantTypeService returns an access response,
// if the resource owner grants the access request.
//
// The authorization server MUST NOT issue a refresh token.
//
// https://tools.ietf.org/html/rfc6749#section-4.2.2
type ImplicitGrantTypeService interface {
	ImplicitGrantTypeResponse(w http.ResponseWriter, req *http.Request, client Client, params url.Values) (*AccessResponse, error)
}

// NewImplicitGrantType creates a new grant type.
func NewImplicitGrantType(service ImplicitGrantTypeService) GrantType {
	return &implicitGT{service}
}

var _ GrantType = (*implicitGT)(nil)
var _ AuthorizeGrantType = (*implicitGT)(nil)

type implicitGT struct {
	service ImplicitGrantTypeService
}

func (gt *implicitGT) Identifier() string {
	return ImplicitGrantType
}

func (gt *implicitGT) ResponseName() string {
	return "token"
}

func (gt *implicitGT) Respond(w http.ResponseWriter, req *http.Request, reqParams url.Values, client Client, redirectURI, state string) {
	access, err := gt.service.ImplicitGrantTypeResponse(w, req, client, reqParams)
	if err != nil {
		redirectWithError(w, req, redirectURI, state, ErrAccessDenied)
	}
	if access == nil {
		return
	}

	access.RefreshToken = ""
	values := access.ToValues()

	redirectWithValues(w, req, redirectURI, state, values)
}

func redirectWithError(w http.ResponseWriter, req *http.Request, redirectURI, state string, err error) {
	values := url.Values{}
	values.Set("error", err.Error())

	redirectWithValues(w, req, redirectURI, state, values)
}

func redirectWithValues(w http.ResponseWriter, req *http.Request, redirectURI, state string, values url.Values) {
	values.Set("state", state)
	redirect := redirectURI + "#" + values.Encode()

	http.Redirect(w, req, redirect, http.StatusFound)
}
