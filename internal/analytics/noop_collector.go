package analytics

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

var _ EventReporter = (*NoopEventReporter)(nil)

type (
	// NoopEventReporter is a no-op EventReporter.
	NoopEventReporter struct{}
)

// NewNoopEventReporter returns a new no-op EventReporter.
func NewNoopEventReporter() EventReporter {
	return &NoopEventReporter{}
}

// Close does nothing.
func (c *NoopEventReporter) Close() {}

// AddUser does nothing.
func (c *NoopEventReporter) AddUser(context.Context, string, map[string]any) error {
	return nil
}

// EventOccurred does nothing.
func (c *NoopEventReporter) EventOccurred(context.Context, types.ServiceEventType, string, map[string]any) error {
	return nil
}
