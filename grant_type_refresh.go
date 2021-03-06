// Copyright (c) 2016 Danilo Bürger <info@danilobuerger.de>

package oauth2

import (
	"context"
	"net/http"
)

// RefreshGrantType is used for refreshing an access token.
//
// https://tools.ietf.org/html/rfc6749#section-6
const RefreshGrantType = "refresh"

// RefreshGrantTypeService returns an access response,
// if the access token request is valid and authorized.
//
// Because refresh tokens are typically long-lasting credentials used to
// request additional access tokens, the refresh token is bound to the
// client to which it was issued.
//
// The authorization server MUST validate the refresh token.
//
// The authorization server MAY issue a new refresh token, in which case
// the client MUST discard the old refresh token and replace it with the
// new refresh token.  The authorization server MAY revoke the old
// refresh token after issuing a new refresh token to the client.  If a
// new refresh token is issued, the refresh token scope MUST be
// identical to that of the refresh token included by the client in the
// request.
//
// https://tools.ietf.org/html/rfc6749#section-6
type RefreshGrantTypeService interface {
	RefreshGrantTypeResponse(ctx context.Context, client Client, refreshToken string) (*AccessResponse, error)
}

// NewRefreshGrantType creates a new grant type.
func NewRefreshGrantType(logger Log, service RefreshGrantTypeService) GrantType {
	return &refreshGT{logger, service}
}

var _ GrantType = (*refreshGT)(nil)
var _ TokenGrantType = (*refreshGT)(nil)

type refreshGT struct {
	logger  Log
	service RefreshGrantTypeService
}

func (gt *refreshGT) Identifier() string {
	return RefreshGrantType
}

func (gt *refreshGT) GrantName() string {
	return "refresh_token"
}

func (gt *refreshGT) Grant(req *http.Request, client Client) (*AccessResponse, error) {
	token := req.PostFormValue("refresh_token")
	if token == "" {
		return nil, ErrInvalidRequest
	}

	access, err := gt.service.RefreshGrantTypeResponse(req.Context(), client, token)
	if err != nil {
		if gt.logger != nil {
			gt.logger.Println(err)
		}
		return nil, ErrInvalidGrant
	}

	return access, nil
}
