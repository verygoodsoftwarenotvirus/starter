package types

import "net/http"

type (
	// CapitalismService describes a structure capable of serving worker-oriented requests.
	CapitalismService interface {
		IncomingWebhookHandler(res http.ResponseWriter, req *http.Request)
	}
)
