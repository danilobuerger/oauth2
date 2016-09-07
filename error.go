// Copyright (c) 2016 Danilo Bürger <info@danilobuerger.de>

package oauth2

import "errors"

// ErrInvalidRequest is returned when:
//
// The request is missing a required parameter, includes an
// unsupported parameter value (other than grant type),
// repeats a parameter, includes multiple credentials,
// utilizes more than one mechanism for authenticating the
// client, or is otherwise malformed.
//
// https://tools.ietf.org/html/rfc6749#section-5.2
var ErrInvalidRequest = errors.New("invalid_request")

// ErrInvalidClient is returned when:
//
// Client authentication failed (e.g., unknown client, no
// client authentication included, or unsupported
// authentication method).  The authorization server MAY
// return an HTTP 401 (Unauthorized) status code to indicate
// which HTTP authentication schemes are supported.  If the
// client attempted to authenticate via the "Authorization"
// request header field, the authorization server MUST
// respond with an HTTP 401 (Unauthorized) status code and
// include the "WWW-Authenticate" response header field
// matching the authentication scheme used by the client.
//
// https://tools.ietf.org/html/rfc6749#section-5.2
var ErrInvalidClient = errors.New("invalid_client")

// ErrInvalidGrant is returned when:
//
// The provided authorization grant (e.g., authorization
// code, resource owner credentials) or refresh token is
// invalid, expired, revoked, does not match the redirection
// URI used in the authorization request, or was issued to
// another client.
//
// https://tools.ietf.org/html/rfc6749#section-5.2
var ErrInvalidGrant = errors.New("invalid_grant")

// ErrUnauthorizedClient is returned when:
//
// The authenticated client is not authorized to use this
// authorization grant type.
//
// https://tools.ietf.org/html/rfc6749#section-5.2
var ErrUnauthorizedClient = errors.New("unauthorized_client")

// ErrUnsupportedGrantType is returned when:
//
// The authorization grant type is not supported by the
// authorization server.
//
// https://tools.ietf.org/html/rfc6749#section-5.2
var ErrUnsupportedGrantType = errors.New("unsupported_grant_type")

// ErrInvalidScope is returned when:
//
// The requested scope is invalid, unknown, malformed, or
// exceeds the scope granted by the resource owner.
//
// https://tools.ietf.org/html/rfc6749#section-5.2
var ErrInvalidScope = errors.New("invalid_scope")

// ErrAccessDenied is returned when:
//
// The resource owner or authorization server denied the
// request.
//
// https://tools.ietf.org/html/rfc6749#section-4.1.2.1
// https://tools.ietf.org/html/rfc6749#section-4.2.2.1
var ErrAccessDenied = errors.New("access_denied")

// ErrUnsupportedResponseType is returned when:
//
// The authorization server does not support obtaining an
// authorization code / access token using this method.
//
// https://tools.ietf.org/html/rfc6749#section-4.1.2.1
// https://tools.ietf.org/html/rfc6749#section-4.2.2.1
var ErrUnsupportedResponseType = errors.New("unsupported_response_type")
