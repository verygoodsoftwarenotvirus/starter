package apiclient

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// GetAuditLogEntry fetches an audit log entry.
func (c *Client) GetAuditLogEntry(ctx context.Context, auditLogEntryID string) (*types.AuditLogEntry, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if auditLogEntryID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AuditLogEntryIDKey, auditLogEntryID)
	tracing.AttachToSpan(span, keys.AuditLogEntryIDKey, auditLogEntryID)

	req, err := c.requestBuilder.BuildGetAuditLogEntryRequest(ctx, auditLogEntryID)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building audit log entry request")
	}

	var apiResponse *types.APIResponse[*types.AuditLogEntry]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "retrieving audit log entry")
	}

	return apiResponse.Data, nil
}

// GetAuditLogEntriesForUser fetches audit log entries for a user.
func (c *Client) GetAuditLogEntriesForUser(ctx context.Context, resourceTypes ...string) (*types.QueryFilteredResult[types.AuditLogEntry], error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.WithValue(keys.AuditLogEntryResourceTypesKey, resourceTypes)

	req, err := c.requestBuilder.BuildGetAuditLogEntriesForUserRequest(ctx, resourceTypes...)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building user audit log entries request")
	}

	var apiResponse *types.APIResponse[[]*types.AuditLogEntry]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "retrieving user audit log entries")
	}

	result := &types.QueryFilteredResult[types.AuditLogEntry]{
		Data:       apiResponse.Data,
		Pagination: *apiResponse.Pagination,
	}

	return result, nil
}

// GetAuditLogEntriesForAccount fetches audit log entries for a user's account.
func (c *Client) GetAuditLogEntriesForAccount(ctx context.Context, resourceTypes ...string) (*types.QueryFilteredResult[types.AuditLogEntry], error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.WithValue(keys.AuditLogEntryResourceTypesKey, resourceTypes)

	req, err := c.requestBuilder.BuildGetAuditLogEntriesForAccountRequest(ctx, resourceTypes...)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building account audit log entries request")
	}

	var apiResponse *types.APIResponse[[]*types.AuditLogEntry]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "retrieving account audit log entries")
	}

	result := &types.QueryFilteredResult[types.AuditLogEntry]{
		Data:       apiResponse.Data,
		Pagination: *apiResponse.Pagination,
	}

	return result, nil
}
