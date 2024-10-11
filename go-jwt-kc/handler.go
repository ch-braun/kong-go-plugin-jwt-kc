package go_jwt_kc

import (
	"errors"
	"github.com/Kong/go-pdk"
	"net/http"
	"strings"
)

const (
	MessageUnexpectedError = "An unexpected error occurred during authentication"
)

func abortWithError(kong *pdk.PDK, err error, message string, statusCode int) {

	if err != nil {
		message = message + " " + err.Error()
	}

	_ = kong.Log.Err(message)
	kong.Response.Exit(statusCode, []byte(message), make(map[string][]string))
}

func (conf Config) Access(kong *pdk.PDK) {
	// Check if preflight request and whether it should be authenticated
	requestMethod, err := kong.Request.GetMethod()
	if err != nil {
		abortWithError(kong, err, MessageUnexpectedError, http.StatusInternalServerError)
		return
	}

	if !conf.RunOnPreflight && strings.EqualFold(requestMethod, http.MethodOptions) {
		return
	}

	clientCredential, err := kong.Client.GetCredential()

	if err != nil {
		abortWithError(kong, err, MessageUnexpectedError, http.StatusInternalServerError)
		return
	}

	if conf.Anonymous != "" && (clientCredential.Id != "" || clientCredential.ConsumerId != "") {
		// we're already authenticated, and we're configured for using anonymous,
		// hence we're in a logical OR between auth methods, and we're already done.
		return
	}

	ok, authError := doAuthentication(&conf, kong)

	if !ok {
		if conf.Anonymous != "" {
			consumer, err := fetchConsumer(conf.Anonymous, kong)
			if err != nil {
				abortWithError(kong, err, MessageUnexpectedError, http.StatusInternalServerError)
				return
			}
			setConsumer(consumer, nil, nil, kong)
		} else {
			if authError == nil {
				abortWithError(kong, errors.New(""), "Unauthorized", http.StatusUnauthorized)
			} else {
				abortWithError(kong, authError.err, authError.message, authError.statusCode)
			}
			return
		}
	}
}
