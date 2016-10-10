// Copyright (c) 2016 Danilo Bürger <info@danilobuerger.de>

package oauth2

import (
	"context"
	"net/http"
)

// ClientGrantType is used by the client using only its client
// credentials (or other supported means of authentication) when the
// client is requesting access to the protected resources under its
// control, or those of another resource owner that have been previously
// arranged with the authorization server (the method of which is beyond
// the scope of this specification).
//
// https://tools.ietf.org/html/rfc6749#section-4.4
const ClientGrantType = "client"

// ClientGrantTypeService returns an access response,
// if the access token request is valid and authorized.
//
// The authorization server MUST authenticate the client.
//
// A refresh token SHOULD NOT be included.
//
// https://tools.ietf.org/html/rfc6749#section-4.4.2
type ClientGrantTypeService interface {
	ClientGrantTypeResponse(ctx context.Context, client Client) (*AccessResponse, error)
}

// NewClientGrantType creates a new grant type.
func NewClientGrantType(service ClientGrantTypeService) GrantType {
	return &clientGT{service}
}

var _ GrantType = (*clientGT)(nil)
var _ TokenGrantType = (*clientGT)(nil)

type clientGT struct {
	service ClientGrantTypeService
}

func (gt *clientGT) Identifier() string {
	return ClientGrantType
}

func (gt *clientGT) GrantName() string {
	return "client_credentials"
}

func (gt *clientGT) Grant(req *http.Request, client Client) (*AccessResponse, error) {
	if !client.IsConfidential() {
		return nil, ErrInvalidClient
	}

	access, err := gt.service.ClientGrantTypeResponse(req.Context(), client)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	return access, nil
}
