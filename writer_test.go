package oauth2

import (
	"errors"
	"net/http"
	"strconv"
	"testing"
)

func TestErrorText(t *testing.T) {
	tests := []struct {
		status   int
		text     string
		expected string
	}{
		{http.StatusContinue, "foo", "foo"},
		{http.StatusSwitchingProtocols, "foo", "foo"},
		{http.StatusOK, "foo", "foo"},
		{http.StatusCreated, "foo", "foo"},
		{http.StatusAccepted, "foo", "foo"},
		{http.StatusNonAuthoritativeInfo, "foo", "foo"},
		{http.StatusNoContent, "foo", "foo"},
		{http.StatusResetContent, "foo", "foo"},
		{http.StatusPartialContent, "foo", "foo"},
		{http.StatusMultipleChoices, "foo", "foo"},
		{http.StatusMovedPermanently, "foo", "foo"},
		{http.StatusFound, "foo", "foo"},
		{http.StatusSeeOther, "foo", "foo"},
		{http.StatusNotModified, "foo", "foo"},
		{http.StatusUseProxy, "foo", "foo"},
		{http.StatusTemporaryRedirect, "foo", "foo"},
		{http.StatusBadRequest, "foo", "foo"},
		{http.StatusUnauthorized, "foo", "foo"},
		{http.StatusPaymentRequired, "foo", "foo"},
		{http.StatusForbidden, "foo", "foo"},
		{http.StatusNotFound, "foo", "foo"},
		{http.StatusMethodNotAllowed, "foo", "foo"},
		{http.StatusNotAcceptable, "foo", "foo"},
		{http.StatusProxyAuthRequired, "foo", "foo"},
		{http.StatusRequestTimeout, "foo", "foo"},
		{http.StatusConflict, "foo", "foo"},
		{http.StatusGone, "foo", "foo"},
		{http.StatusLengthRequired, "foo", "foo"},
		{http.StatusPreconditionFailed, "foo", "foo"},
		{http.StatusRequestEntityTooLarge, "foo", "foo"},
		{http.StatusRequestURITooLong, "foo", "foo"},
		{http.StatusUnsupportedMediaType, "foo", "foo"},
		{http.StatusRequestedRangeNotSatisfiable, "foo", "foo"},
		{http.StatusExpectationFailed, "foo", "foo"},
		{http.StatusTeapot, "foo", "foo"},
		{http.StatusPreconditionRequired, "foo", "foo"},
		{http.StatusTooManyRequests, "foo", "foo"},
		{http.StatusRequestHeaderFieldsTooLarge, "foo", "foo"},
		{http.StatusUnavailableForLegalReasons, "foo", "foo"},
		{http.StatusInternalServerError, "foo", http.StatusText(http.StatusInternalServerError)},
		{http.StatusNotImplemented, "foo", http.StatusText(http.StatusNotImplemented)},
		{http.StatusBadGateway, "foo", http.StatusText(http.StatusBadGateway)},
		{http.StatusServiceUnavailable, "foo", http.StatusText(http.StatusServiceUnavailable)},
		{http.StatusGatewayTimeout, "foo", http.StatusText(http.StatusGatewayTimeout)},
		{http.StatusHTTPVersionNotSupported, "foo", http.StatusText(http.StatusHTTPVersionNotSupported)},
		{http.StatusNetworkAuthenticationRequired, "foo", http.StatusText(http.StatusNetworkAuthenticationRequired)},
	}

	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.status), func(t *testing.T) {
			got := errorText(tt.status, errors.New(tt.text))
			if got != tt.expected {
				t.Errorf("errorText(%v, %v) => %v, expected %v", tt.status, tt.text, got, tt.expected)
			}
		})
	}
}

func TestIsServerError(t *testing.T) {
	tests := []struct {
		status   int
		expected bool
	}{
		{http.StatusContinue, false},
		{http.StatusSwitchingProtocols, false},
		{http.StatusOK, false},
		{http.StatusCreated, false},
		{http.StatusAccepted, false},
		{http.StatusNonAuthoritativeInfo, false},
		{http.StatusNoContent, false},
		{http.StatusResetContent, false},
		{http.StatusPartialContent, false},
		{http.StatusMultipleChoices, false},
		{http.StatusMovedPermanently, false},
		{http.StatusFound, false},
		{http.StatusSeeOther, false},
		{http.StatusNotModified, false},
		{http.StatusUseProxy, false},
		{http.StatusTemporaryRedirect, false},
		{http.StatusBadRequest, false},
		{http.StatusUnauthorized, false},
		{http.StatusPaymentRequired, false},
		{http.StatusForbidden, false},
		{http.StatusNotFound, false},
		{http.StatusMethodNotAllowed, false},
		{http.StatusNotAcceptable, false},
		{http.StatusProxyAuthRequired, false},
		{http.StatusRequestTimeout, false},
		{http.StatusConflict, false},
		{http.StatusGone, false},
		{http.StatusLengthRequired, false},
		{http.StatusPreconditionFailed, false},
		{http.StatusRequestEntityTooLarge, false},
		{http.StatusRequestURITooLong, false},
		{http.StatusUnsupportedMediaType, false},
		{http.StatusRequestedRangeNotSatisfiable, false},
		{http.StatusExpectationFailed, false},
		{http.StatusTeapot, false},
		{http.StatusPreconditionRequired, false},
		{http.StatusTooManyRequests, false},
		{http.StatusRequestHeaderFieldsTooLarge, false},
		{http.StatusUnavailableForLegalReasons, false},
		{http.StatusInternalServerError, true},
		{http.StatusNotImplemented, true},
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
		{http.StatusGatewayTimeout, true},
		{http.StatusHTTPVersionNotSupported, true},
		{http.StatusNetworkAuthenticationRequired, true},
	}

	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.status), func(t *testing.T) {
			got := isServerError(tt.status)
			if got != tt.expected {
				t.Errorf("isServerError(%v) => %v, expected %v", tt.status, got, tt.expected)
			}
		})
	}
}
