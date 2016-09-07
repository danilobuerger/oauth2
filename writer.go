// Copyright (c) 2016 Danilo Bürger <info@danilobuerger.de>

package oauth2

import (
	"encoding/json"
	"net/http"
)

func writeError(w http.ResponseWriter, logger Log, status int, err error, state string) {
	if isServerError(status) {
		logger.Println(err)
	}

	resp := struct {
		Error string `json:"error"`
		State string `json:"state,omitempty"`
	}{
		Error: errorText(status, err),
		State: state,
	}

	data, mErr := json.Marshal(resp)
	if mErr != nil {
		logger.Println(err)
		status = http.StatusInternalServerError
		data = nil
	}

	writeData(w, status, data, nil)
}

func writeJSON(w http.ResponseWriter, logger Log, status int, resp interface{}, headers map[string]string) {
	if resp == nil {
		writeData(w, status, nil, headers)
		return
	}

	data, err := json.Marshal(resp)
	if err != nil {
		writeError(w, logger, http.StatusInternalServerError, err, "")
		return
	}

	writeData(w, status, data, headers)
}

func writeData(w http.ResponseWriter, status int, data []byte, headers map[string]string) {
	header := w.Header()
	for k, v := range headers {
		header.Set(k, v)
	}

	header.Set("Content-Type", "application/json; charset=utf-8")

	w.WriteHeader(status)
	w.Write(data)
}

func errorText(status int, err error) string {
	if isServerError(status) {
		return http.StatusText(status)
	}

	return err.Error()
}

func isServerError(status int) bool {
	return status >= 500
}
