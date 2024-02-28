package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres/generated"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

var (
	_ types.OAuth2ClientDataManager = (*Querier)(nil)
)

// GetOAuth2ClientByClientID gets an OAuth2 client from the database.
func (q *Querier) GetOAuth2ClientByClientID(ctx context.Context, clientID string) (*types.OAuth2Client, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if clientID == "" {
		return nil, ErrEmptyInputProvided
	}
	logger = logger.WithValue(keys.OAuth2ClientClientIDKey, clientID)
	tracing.AttachToSpan(span, keys.OAuth2ClientClientIDKey, clientID)

	result, err := q.generatedQuerier.GetOAuth2ClientByClientID(ctx, q.db, clientID)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "fetching oauth2 client")
	}

	client := &types.OAuth2Client{
		CreatedAt:    result.CreatedAt,
		ArchivedAt:   database.TimePointerFromNullTime(result.ArchivedAt),
		Name:         result.Name,
		Description:  result.Description,
		ClientID:     result.ClientID,
		ID:           result.ID,
		ClientSecret: result.ClientSecret,
	}

	return client, nil
}

// GetOAuth2ClientByDatabaseID gets an OAuth2 client from the database.
func (q *Querier) GetOAuth2ClientByDatabaseID(ctx context.Context, clientID string) (*types.OAuth2Client, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if clientID == "" {
		return nil, ErrEmptyInputProvided
	}
	logger = logger.WithValue(keys.OAuth2ClientClientIDKey, clientID)
	tracing.AttachToSpan(span, keys.OAuth2ClientClientIDKey, clientID)

	result, err := q.generatedQuerier.GetOAuth2ClientByDatabaseID(ctx, q.db, clientID)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "fetching oauth2 client")
	}

	client := &types.OAuth2Client{
		CreatedAt:    result.CreatedAt,
		ArchivedAt:   database.TimePointerFromNullTime(result.ArchivedAt),
		Name:         result.Name,
		Description:  result.Description,
		ClientID:     result.ClientID,
		ID:           result.ID,
		ClientSecret: result.ClientSecret,
	}

	return client, nil
}

// GetOAuth2Clients gets a list of OAuth2 clients.
func (q *Querier) GetOAuth2Clients(ctx context.Context, filter *types.QueryFilter) (x *types.QueryFilteredResult[types.OAuth2Client], err error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if filter == nil {
		filter = types.DefaultQueryFilter()
	}
	logger = filter.AttachToLogger(logger)
	tracing.AttachQueryFilterToSpan(span, filter)

	x = &types.QueryFilteredResult[types.OAuth2Client]{
		Pagination: filter.ToPagination(),
	}

	results, err := q.generatedQuerier.GetOAuth2Clients(ctx, q.db, &generated.GetOAuth2ClientsParams{
		CreatedBefore: database.NullTimeFromTimePointer(filter.CreatedBefore),
		CreatedAfter:  database.NullTimeFromTimePointer(filter.CreatedAfter),
		QueryOffset:   database.NullInt32FromUint16(filter.QueryOffset()),
		QueryLimit:    database.NullInt32FromUint8Pointer(filter.Limit),
	})
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "fetching oauth2 clients")
	}

	for _, result := range results {
		x.Data = append(x.Data, &types.OAuth2Client{
			CreatedAt:    result.CreatedAt,
			ArchivedAt:   database.TimePointerFromNullTime(result.ArchivedAt),
			Name:         result.Name,
			Description:  result.Description,
			ClientID:     result.ClientID,
			ID:           result.ID,
			ClientSecret: result.ClientSecret,
		})
		x.FilteredCount = uint64(result.FilteredCount)
		x.TotalCount = uint64(result.TotalCount)
	}

	return x, nil
}

// CreateOAuth2Client creates an OAuth2 client.
func (q *Querier) CreateOAuth2Client(ctx context.Context, input *types.OAuth2ClientDatabaseCreationInput) (*types.OAuth2Client, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	logger := q.logger.WithValues(map[string]any{
		keys.OAuth2ClientClientIDKey: input.ClientID,
	})

	if writeErr := q.generatedQuerier.CreateOAuth2Client(ctx, q.db, &generated.CreateOAuth2ClientParams{
		ID:           input.ID,
		Name:         input.Name,
		ClientID:     input.ClientID,
		ClientSecret: input.ClientSecret,
	}); writeErr != nil {
		return nil, observability.PrepareError(writeErr, span, "creating OAuth2 client")
	}

	tracing.AttachToSpan(span, keys.OAuth2ClientClientIDKey, input.ID)

	client := &types.OAuth2Client{
		ID:           input.ID,
		Name:         input.Name,
		ClientID:     input.ClientID,
		ClientSecret: input.ClientSecret,
		CreatedAt:    q.currentTime(),
	}

	logger.Info("OAuth2 client created")

	return client, nil
}

// ArchiveOAuth2Client archives an OAuth2 client.
func (q *Querier) ArchiveOAuth2Client(ctx context.Context, clientID string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if clientID == "" {
		return ErrNilInputProvided
	}
	tracing.AttachToSpan(span, keys.OAuth2ClientClientIDKey, clientID)
	logger := q.logger.WithValue(keys.OAuth2ClientIDKey, clientID)

	if _, err := q.generatedQuerier.ArchiveOAuth2Client(ctx, q.db, clientID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return observability.PrepareAndLogError(err, logger, span, "archiving OAuth2 client")
	}

	logger.Info("OAuth2 client archived")

	return nil
}
