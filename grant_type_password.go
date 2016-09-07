// Copyright (c) 2016 Danilo Bürger <info@danilobuerger.de>

package oauth2

import (
	"context"
	"net/http"
)

// PasswordGrantType (resource owner password credentials grant type) is suitable in
// cases where the resource owner has a trust relationship with the
// client, such as the device operating system or a highly privileged
// application.  The authorization server should take special care when
// enabling this grant type and only allow it when other flows are not
// viable.
//
// https://tools.ietf.org/html/rfc6749#section-4.3
const PasswordGrantType = "password"

// PasswordGrantTypeService returns an access response,
// if the access token request is valid and authorized.
//
// The authorization server MUST validate the resource owner password
// credentials using its existing password validation algorithm.
//
// Since this access token request utilizes the resource owner's
// password, the authorization server MUST protect the endpoint against
// brute force attacks (e.g., using rate-limitation or generating
// alerts).
//
// https://tools.ietf.org/html/rfc6749#section-4.3.2
type PasswordGrantTypeService interface {
	PasswordGrantTypeResponse(ctx context.Context, client Client, username, password string) (*AccessResponse, error)
}

// NewPasswordGrantType creates a new grant type.
func NewPasswordGrantType(service PasswordGrantTypeService) GrantType {
	return &passwordGT{service}
}

var _ GrantType = (*passwordGT)(nil)
var _ TokenGrantType = (*passwordGT)(nil)

type passwordGT struct {
	service PasswordGrantTypeService
}

func (gt *passwordGT) Identifier() string {
	return PasswordGrantType
}

func (gt *passwordGT) GrantName() string {
	return "password"
}

func (gt *passwordGT) Grant(req *http.Request, client Client) (*AccessResponse, error) {
	username := req.PostFormValue("username")
	password := req.PostFormValue("password")
	if username == "" || password == "" {
		return nil, ErrInvalidRequest
	}

	access, err := gt.service.PasswordGrantTypeResponse(req.Context(), client, username, password)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	return access, nil
}
