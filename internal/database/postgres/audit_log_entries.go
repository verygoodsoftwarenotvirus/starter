package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres/generated"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

var (
	_ types.AuditLogEntryDataManager = (*Querier)(nil)
)

// GetAuditLogEntry fetches an audit log entry from the database.
func (q *Querier) GetAuditLogEntry(ctx context.Context, auditLogEntryID string) (*types.AuditLogEntry, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if auditLogEntryID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AuditLogEntryIDKey, auditLogEntryID)
	tracing.AttachToSpan(span, keys.AuditLogEntryIDKey, auditLogEntryID)

	result, err := q.generatedQuerier.GetAuditLogEntry(ctx, q.db, auditLogEntryID)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "fetching audit log entry")
	}

	auditLogEntry := &types.AuditLogEntry{
		CreatedAt:        result.CreatedAt,
		BelongsToAccount: database.StringPointerFromNullString(result.BelongsToAccount),
		ID:               result.ID,
		ResourceType:     result.ResourceType,
		RelevantID:       result.RelevantID,
		EventType:        types.AuditLogEntryEventType(result.EventType),
		BelongsToUser:    database.StringFromNullString(result.BelongsToUser),
	}

	if err = json.Unmarshal(result.Changes, &auditLogEntry.Changes); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "parsing audit log entry JSON data")
	}

	return auditLogEntry, nil
}

// GetAuditLogEntriesForUser fetches a list of audit log entries from the database that meet a particular filter.
func (q *Querier) GetAuditLogEntriesForUser(ctx context.Context, userID string, filter *types.QueryFilter) (*types.QueryFilteredResult[types.AuditLogEntry], error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if userID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	if filter == nil {
		filter = types.DefaultQueryFilter()
	}

	tracing.AttachQueryFilterToSpan(span, filter)
	x := &types.QueryFilteredResult[types.AuditLogEntry]{
		Pagination: filter.ToPagination(),
	}

	results, err := q.generatedQuerier.GetAuditLogEntriesForUser(ctx, q.db, &generated.GetAuditLogEntriesForUserParams{
		BelongsToUser: database.NullStringFromString(userID),
		CreatedBefore: database.NullTimeFromTimePointer(filter.CreatedBefore),
		CreatedAfter:  database.NullTimeFromTimePointer(filter.CreatedAfter),
		QueryOffset:   database.NullInt32FromUint16(filter.QueryOffset()),
		QueryLimit:    database.NullInt32FromUint8Pointer(filter.Limit),
	})
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "fetching audit log entries from database")
	}

	for _, result := range results {
		auditLogEntry := &types.AuditLogEntry{
			CreatedAt:        result.CreatedAt,
			BelongsToAccount: database.StringPointerFromNullString(result.BelongsToAccount),
			ID:               result.ID,
			ResourceType:     result.ResourceType,
			RelevantID:       result.RelevantID,
			EventType:        types.AuditLogEntryEventType(result.EventType),
			BelongsToUser:    database.StringFromNullString(result.BelongsToUser),
		}

		if err = json.Unmarshal(result.Changes, &auditLogEntry.Changes); err != nil {
			return nil, observability.PrepareAndLogError(err, logger, span, "parsing audit log entry JSON data")
		}

		x.Data = append(x.Data, auditLogEntry)
		x.FilteredCount = uint64(result.FilteredCount)
		x.TotalCount = uint64(result.TotalCount)
	}

	return x, nil
}

// GetAuditLogEntriesForUserAndResourceType fetches a list of audit log entries from the database that meet a particular filter.
func (q *Querier) GetAuditLogEntriesForUserAndResourceType(ctx context.Context, userID string, resourceTypes []string, filter *types.QueryFilter) (*types.QueryFilteredResult[types.AuditLogEntry], error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if userID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	if len(resourceTypes) == 0 {
		return nil, ErrEmptyInputProvided
	}
	logger = logger.WithValue(keys.AuditLogEntryResourceTypesKey, resourceTypes)
	tracing.AttachToSpan(span, keys.AuditLogEntryResourceTypesKey, resourceTypes)

	if filter == nil {
		filter = types.DefaultQueryFilter()
	}

	tracing.AttachQueryFilterToSpan(span, filter)
	x := &types.QueryFilteredResult[types.AuditLogEntry]{
		Pagination: filter.ToPagination(),
	}

	results, err := q.generatedQuerier.GetAuditLogEntriesForUserAndResourceType(ctx, q.db, &generated.GetAuditLogEntriesForUserAndResourceTypeParams{
		BelongsToUser: database.NullStringFromString(userID),
		Resources:     resourceTypes,
		CreatedBefore: database.NullTimeFromTimePointer(filter.CreatedBefore),
		CreatedAfter:  database.NullTimeFromTimePointer(filter.CreatedAfter),
		QueryOffset:   database.NullInt32FromUint16(filter.QueryOffset()),
		QueryLimit:    database.NullInt32FromUint8Pointer(filter.Limit),
	})
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "fetching audit log entries from database")
	}

	for _, result := range results {
		auditLogEntry := &types.AuditLogEntry{
			CreatedAt:        result.CreatedAt,
			BelongsToAccount: database.StringPointerFromNullString(result.BelongsToAccount),
			ID:               result.ID,
			ResourceType:     result.ResourceType,
			RelevantID:       result.RelevantID,
			EventType:        types.AuditLogEntryEventType(result.EventType),
			BelongsToUser:    database.StringFromNullString(result.BelongsToUser),
		}

		if err = json.Unmarshal(result.Changes, &auditLogEntry.Changes); err != nil {
			return nil, observability.PrepareAndLogError(err, logger, span, "parsing audit log entry JSON data")
		}

		x.Data = append(x.Data, auditLogEntry)
		x.FilteredCount = uint64(result.FilteredCount)
		x.TotalCount = uint64(result.TotalCount)
	}

	return x, nil
}

// GetAuditLogEntriesForAccount fetches a list of audit log entries from the database that meet a particular filter.
func (q *Querier) GetAuditLogEntriesForAccount(ctx context.Context, accountID string, filter *types.QueryFilter) (*types.QueryFilteredResult[types.AuditLogEntry], error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if accountID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AccountIDKey, accountID)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	if filter == nil {
		filter = types.DefaultQueryFilter()
	}

	tracing.AttachQueryFilterToSpan(span, filter)
	x := &types.QueryFilteredResult[types.AuditLogEntry]{
		Pagination: filter.ToPagination(),
	}

	results, err := q.generatedQuerier.GetAuditLogEntriesForAccount(ctx, q.db, &generated.GetAuditLogEntriesForAccountParams{
		BelongsToAccount: database.NullStringFromString(accountID),
		CreatedBefore:    database.NullTimeFromTimePointer(filter.CreatedBefore),
		CreatedAfter:     database.NullTimeFromTimePointer(filter.CreatedAfter),
		QueryOffset:      database.NullInt32FromUint16(filter.QueryOffset()),
		QueryLimit:       database.NullInt32FromUint8Pointer(filter.Limit),
	})
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "fetching audit log entries from database")
	}

	for _, result := range results {
		auditLogEntry := &types.AuditLogEntry{
			CreatedAt:        result.CreatedAt,
			BelongsToAccount: database.StringPointerFromNullString(result.BelongsToAccount),
			ID:               result.ID,
			ResourceType:     result.ResourceType,
			RelevantID:       result.RelevantID,
			EventType:        types.AuditLogEntryEventType(result.EventType),
			BelongsToUser:    database.StringFromNullString(result.BelongsToUser),
		}

		if err = json.Unmarshal(result.Changes, &auditLogEntry.Changes); err != nil {
			return nil, observability.PrepareAndLogError(err, logger, span, "parsing audit log entry JSON data")
		}

		x.Data = append(x.Data, auditLogEntry)
		x.FilteredCount = uint64(result.FilteredCount)
		x.TotalCount = uint64(result.TotalCount)
	}

	return x, nil
}

// GetAuditLogEntriesForAccountAndResourceType fetches a list of audit log entries from the database that meet a particular filter.
func (q *Querier) GetAuditLogEntriesForAccountAndResourceType(ctx context.Context, accountID string, resourceTypes []string, filter *types.QueryFilter) (*types.QueryFilteredResult[types.AuditLogEntry], error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if accountID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AccountIDKey, accountID)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	if len(resourceTypes) == 0 {
		return nil, ErrEmptyInputProvided
	}
	logger = logger.WithValue(keys.AuditLogEntryResourceTypesKey, resourceTypes)
	tracing.AttachToSpan(span, keys.AuditLogEntryResourceTypesKey, resourceTypes)

	if filter == nil {
		filter = types.DefaultQueryFilter()
	}

	tracing.AttachQueryFilterToSpan(span, filter)
	x := &types.QueryFilteredResult[types.AuditLogEntry]{
		Pagination: filter.ToPagination(),
	}

	results, err := q.generatedQuerier.GetAuditLogEntriesForAccountAndResourceType(ctx, q.db, &generated.GetAuditLogEntriesForAccountAndResourceTypeParams{
		BelongsToAccount: database.NullStringFromString(accountID),
		Resources:        resourceTypes,
		CreatedBefore:    database.NullTimeFromTimePointer(filter.CreatedBefore),
		CreatedAfter:     database.NullTimeFromTimePointer(filter.CreatedAfter),
		QueryOffset:      database.NullInt32FromUint16(filter.QueryOffset()),
		QueryLimit:       database.NullInt32FromUint8Pointer(filter.Limit),
	})
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "fetching audit log entries from database")
	}

	for _, result := range results {
		auditLogEntry := &types.AuditLogEntry{
			CreatedAt:        result.CreatedAt,
			BelongsToAccount: database.StringPointerFromNullString(result.BelongsToAccount),
			ID:               result.ID,
			ResourceType:     result.ResourceType,
			RelevantID:       result.RelevantID,
			EventType:        types.AuditLogEntryEventType(result.EventType),
			BelongsToUser:    database.StringFromNullString(result.BelongsToUser),
		}

		if err = json.Unmarshal(result.Changes, &auditLogEntry.Changes); err != nil {
			return nil, observability.PrepareAndLogError(err, logger, span, "parsing audit log entry JSON data")
		}

		x.Data = append(x.Data, auditLogEntry)
		x.FilteredCount = uint64(result.FilteredCount)
		x.TotalCount = uint64(result.TotalCount)
	}

	return x, nil
}

// createAuditLogEntry creates an audit log entry in a database.
func (q *Querier) createAuditLogEntry(ctx context.Context, querier database.SQLQueryExecutor, input *types.AuditLogEntryDatabaseCreationInput) (*types.AuditLogEntry, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	tracing.AttachToSpan(span, keys.AccountIDKey, input.BelongsToAccount)
	logger = logger.WithValue(keys.AccountIDKey, input.BelongsToAccount)

	tracing.AttachToSpan(span, keys.UserIDKey, input.BelongsToUser)
	logger = logger.WithValue(keys.UserIDKey, input.BelongsToUser)

	logger.Debug("createAuditLogEntry invoked")

	marshaledChanges, err := json.Marshal(input.Changes)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "serializing audit log change list")
	}

	if err = q.generatedQuerier.CreateAuditLogEntry(ctx, querier, &generated.CreateAuditLogEntryParams{
		ID:               input.ID,
		ResourceType:     input.ResourceType,
		RelevantID:       input.RelevantID,
		EventType:        generated.AuditLogEventType(input.EventType),
		Changes:          marshaledChanges,
		BelongsToUser:    sql.NullString{String: input.BelongsToUser, Valid: strings.TrimSpace(input.BelongsToUser) != ""},
		BelongsToAccount: database.NullStringFromStringPointer(input.BelongsToAccount),
	}); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "performing audit log creation query")
	}

	x := &types.AuditLogEntry{
		ID:               input.ID,
		Changes:          input.Changes,
		BelongsToAccount: input.BelongsToAccount,
		CreatedAt:        q.currentTime(),
		ResourceType:     input.ResourceType,
		RelevantID:       input.RelevantID,
		EventType:        input.EventType,
		BelongsToUser:    input.BelongsToUser,
	}

	tracing.AttachToSpan(span, keys.AuditLogEntryIDKey, x.ID)

	return x, nil
}
