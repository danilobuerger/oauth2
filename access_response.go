// Copyright (c) 2016 Danilo Bürger <info@danilobuerger.de>

package oauth2

import (
	"encoding"
	"net/url"
	"strconv"
)

// AccessResponse holds a valid and authorized access response.
type AccessResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	Info         map[string]interface{}
}

// ToMap converts the access response to a map.
func (r *AccessResponse) ToMap() map[string]interface{} {
	m := r.Info

	m["access_token"] = r.AccessToken
	m["token_type"] = r.TokenType
	m["expires_in"] = r.ExpiresIn

	if r.RefreshToken != "" {
		m["refresh_token"] = r.RefreshToken
	}

	return m
}

// ToValues converts the access response to values.
func (r *AccessResponse) ToValues() url.Values {
	values := url.Values{}
	for k, vi := range r.Info {
		if vs, ok := vi.([]string); ok {
			for _, v := range vs {
				values.Add(k, v)
			}
		} else if v, ok := vi.(string); ok {
			values.Set(k, v)
		} else if v, ok := vi.(bool); ok {
			values.Set(k, strconv.FormatBool(v))
		} else if v, ok := vi.(encoding.TextMarshaler); ok {
			text, err := v.MarshalText()
			if err == nil {
				values.Set(k, string(text))
			}
		}
	}

	values.Set("access_token", r.AccessToken)
	values.Set("token_type", r.TokenType)
	values.Set("expires_in", strconv.FormatInt(r.ExpiresIn, 10))

	return values
}
