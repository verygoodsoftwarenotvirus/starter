package analytics

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

type (
	// EventReporter collects data about customers.
	EventReporter interface {
		Close()
		AddUser(ctx context.Context, userID string, properties map[string]any) error
		EventOccurred(ctx context.Context, event types.ServiceEventType, userID string, properties map[string]any) error
	}
)
