package postgres

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres/generated"
	"github.com/verygoodsoftwarenotvirus/starter/internal/identifiers"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	resourceTypeUserNotifications = "user_notifications"
)

var (
	_ types.UserNotificationDataManager = (*Querier)(nil)
)

// UserNotificationExists fetches whether a user notification exists from the database.
func (q *Querier) UserNotificationExists(ctx context.Context, userID, userNotificationID string) (exists bool, err error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if userID == "" {
		return false, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	if userNotificationID == "" {
		return false, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.UserNotificationIDKey, userNotificationID)
	tracing.AttachToSpan(span, keys.UserNotificationIDKey, userNotificationID)

	result, err := q.generatedQuerier.CheckUserNotificationExistence(ctx, q.db, &generated.CheckUserNotificationExistenceParams{
		ID:            userNotificationID,
		BelongsToUser: userID,
	})
	if err != nil {
		return false, observability.PrepareAndLogError(err, logger, span, "performing user notification existence check")
	}

	return result, nil
}

// GetUserNotification fetches a user notification from the database.
func (q *Querier) GetUserNotification(ctx context.Context, userID, userNotificationID string) (*types.UserNotification, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if userID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	if userNotificationID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.UserNotificationIDKey, userNotificationID)
	tracing.AttachToSpan(span, keys.UserNotificationIDKey, userNotificationID)

	result, err := q.generatedQuerier.GetUserNotification(ctx, q.db, &generated.GetUserNotificationParams{
		BelongsToUser: userID,
		ID:            userNotificationID,
	})
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "fetching user notification")
	}

	userNotification := &types.UserNotification{
		CreatedAt:     result.CreatedAt,
		LastUpdatedAt: database.TimePointerFromNullTime(result.LastUpdatedAt),
		ID:            result.ID,
		Content:       result.Content,
		Status:        string(result.Status),
		BelongsToUser: result.BelongsToUser,
	}

	return userNotification, nil
}

// GetUserNotifications fetches a list of user notifications from the database that meet a particular filter.
func (q *Querier) GetUserNotifications(ctx context.Context, userID string, filter *types.QueryFilter) (x *types.QueryFilteredResult[types.UserNotification], err error) {
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
	logger = filter.AttachToLogger(logger)
	tracing.AttachQueryFilterToSpan(span, filter)

	x = &types.QueryFilteredResult[types.UserNotification]{
		Pagination: filter.ToPagination(),
	}

	results, err := q.generatedQuerier.GetUserNotificationsForUser(ctx, q.db, &generated.GetUserNotificationsForUserParams{
		UserID:        userID,
		CreatedBefore: database.NullTimeFromTimePointer(filter.CreatedBefore),
		CreatedAfter:  database.NullTimeFromTimePointer(filter.CreatedAfter),
		UpdatedBefore: database.NullTimeFromTimePointer(filter.UpdatedBefore),
		UpdatedAfter:  database.NullTimeFromTimePointer(filter.UpdatedAfter),
		QueryOffset:   database.NullInt32FromUint16(filter.QueryOffset()),
		QueryLimit:    database.NullInt32FromUint8Pointer(filter.Limit),
	})
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "executing user notifications list retrieval query")
	}

	for _, result := range results {
		userNotification := &types.UserNotification{
			CreatedAt:     result.CreatedAt,
			LastUpdatedAt: database.TimePointerFromNullTime(result.LastUpdatedAt),
			ID:            result.ID,
		}

		x.Data = append(x.Data, userNotification)
		x.FilteredCount = uint64(result.FilteredCount)
		x.TotalCount = uint64(result.TotalCount)
	}

	return x, nil
}

// CreateUserNotification creates a user notification in the database.
func (q *Querier) CreateUserNotification(ctx context.Context, input *types.UserNotificationDatabaseCreationInput) (*types.UserNotification, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}
	tracing.AttachToSpan(span, keys.UserNotificationIDKey, input.ID)
	logger := q.logger.WithValue(keys.UserNotificationIDKey, input.ID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	// create the user notification.
	if err = q.generatedQuerier.CreateUserNotification(ctx, tx, &generated.CreateUserNotificationParams{
		ID:            input.ID,
		Content:       input.Content,
		BelongsToUser: input.BelongsToUser,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return nil, observability.PrepareAndLogError(err, logger, span, "performing user notification creation query")
	}

	x := &types.UserNotification{
		ID:            input.ID,
		CreatedAt:     q.currentTime(),
		Content:       input.Content,
		Status:        types.UserNotificationStatusTypeUnread,
		BelongsToUser: input.BelongsToUser,
	}
	tracing.AttachToSpan(span, keys.UserNotificationIDKey, x.ID)
	logger.Info("user notification created")

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUserNotifications,
		RelevantID:    x.ID,
		EventType:     types.AuditLogEventTypeCreated,
		BelongsToUser: x.BelongsToUser,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return nil, observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	return x, nil
}

// UpdateUserNotification updates a particular user notification.
func (q *Querier) UpdateUserNotification(ctx context.Context, updated *types.UserNotification) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if updated == nil {
		return ErrNilInputProvided
	}
	logger := q.logger.WithValue(keys.UserNotificationIDKey, updated.ID)
	tracing.AttachToSpan(span, keys.UserNotificationIDKey, updated.ID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	if _, err = q.generatedQuerier.UpdateUserNotification(ctx, tx, &generated.UpdateUserNotificationParams{
		Status: generated.UserNotificationStatus(updated.Status),
		ID:     updated.ID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "updating user notification")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUserNotifications,
		RelevantID:    updated.ID,
		EventType:     types.AuditLogEventTypeUpdated,
		BelongsToUser: updated.BelongsToUser,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("user notification updated")

	return nil
}
