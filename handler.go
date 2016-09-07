// Copyright (c) 2016 Danilo Bürger <info@danilobuerger.de>

package oauth2

import (
	"io/ioutil"
	"log"
	"net/http"
)

// Handler provides the oauth2 protocol endpoints:
//
// The authorization process utilizes two authorization server endpoints
// (HTTP resources):
//
// o Authorization endpoint - used by the client to obtain
// authorization from the resource owner via user-agent redirection.
//
// o Token endpoint - used by the client to exchange an authorization
// grant for an access token, typically with client authentication.
//
// https://tools.ietf.org/html/rfc6749#section-3
type Handler struct {
	storer       Storer
	logger       Log
	tokenGTs     map[string]TokenGrantType
	authorizeGTs map[string]AuthorizeGrantType
}

// NewHandler creates a new oauth2 handler.
func NewHandler(storer Storer, logger Log, gts ...GrantType) *Handler {
	if logger == nil {
		logger = log.New(ioutil.Discard, "", 0)
	}

	tokenGTs := make(map[string]TokenGrantType, len(gts))
	authorizeGTs := make(map[string]AuthorizeGrantType, len(gts))

	for _, gt := range gts {
		if tgt, ok := gt.(TokenGrantType); ok {
			tokenGTs[tgt.GrantName()] = tgt
		}
		if agt, ok := gt.(AuthorizeGrantType); ok {
			authorizeGTs[agt.ResponseName()] = agt
		}
	}

	return &Handler{
		storer:       storer,
		logger:       logger,
		tokenGTs:     tokenGTs,
		authorizeGTs: authorizeGTs,
	}
}

func (h *Handler) clientFromRequest(req *http.Request, grantType GrantType) (Client, error) {
	clientID := req.FormValue("client_id")
	if clientID == "" {
		return nil, ErrInvalidRequest
	}

	client, err := h.storer.FindClient(clientID)
	if err != nil || client == nil {
		return nil, ErrInvalidClient
	}

	if !client.IsAllowedGrantType(grantType.Identifier()) {
		return nil, ErrUnauthorizedClient
	}

	return client, nil
}

// Token is used by the client to obtain an access token by
// presenting its authorization grant or refresh token. The token
// endpoint is used with every authorization grant except for the
// implicit grant type (since an access token is issued directly).
//
// https://tools.ietf.org/html/rfc6749#section-3.2
func (h *Handler) Token(w http.ResponseWriter, req *http.Request) {
	grantName := req.PostFormValue("grant_type")
	if grantName == "" {
		writeError(w, h.logger, http.StatusBadRequest, ErrInvalidRequest, "")
		return
	}

	grantType, ok := h.tokenGTs[grantName]
	if !ok {
		writeError(w, h.logger, http.StatusBadRequest, ErrUnsupportedGrantType, "")
		return
	}

	client, err := h.clientFromRequest(req, grantType)
	if err != nil {
		writeError(w, h.logger, http.StatusBadRequest, err, "")
		return
	}

	access, err := grantType.Grant(req, client)
	if err != nil {
		writeError(w, h.logger, http.StatusBadRequest, err, "")
		return
	}

	body := access.Info

	body["access_token"] = access.AccessToken
	body["token_type"] = access.TokenType
	body["expires_in"] = access.ExpiresIn

	if access.RefreshToken != "" {
		body["refresh_token"] = access.RefreshToken
	}

	writeJSON(w, h.logger, http.StatusOK, body, map[string]string{
		"Cache-Control": "no-store",
		"Pragma":        "no-cache",
	})
}

// Authorize is used to interact with the resource
// owner and obtain an authorization grant. The authorization server
// MUST first verify the identity of the resource owner. The way in
// which the authorization server authenticates the resource owner
// (e.g., username and password login, session cookies) is beyond the
// scope of this specification.
//
// https://tools.ietf.org/html/rfc6749#section-3.1
func (h *Handler) Authorize(w http.ResponseWriter, req *http.Request) {
	responseName := req.FormValue("response_type")
	redirectURI := req.FormValue("redirect_uri")
	state := req.FormValue("state")
	if responseName == "" || redirectURI == "" || state == "" {
		writeError(w, h.logger, http.StatusBadRequest, ErrInvalidRequest, state)
		return
	}

	grantType, ok := h.authorizeGTs[responseName]
	if !ok {
		writeError(w, h.logger, http.StatusBadRequest, ErrUnsupportedResponseType, state)
		return
	}

	client, err := h.clientFromRequest(req, grantType)
	if err != nil {
		writeError(w, h.logger, http.StatusBadRequest, err, state)
		return
	}

	if !client.IsAllowedRedirectURI(redirectURI) {
		writeError(w, h.logger, http.StatusBadRequest, ErrInvalidRequest, state)
		return
	}

	grantType.Respond(w, req, client, &AuthorizeRequest{
		URL:          req.URL,
		ResponseType: responseName,
		ClientID:     client.Identifier(),
		RedirectURI:  redirectURI,
		State:        state,
	})
}
