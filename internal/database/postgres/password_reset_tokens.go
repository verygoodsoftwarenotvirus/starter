package postgres

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres/generated"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

var (
	_ types.PasswordResetTokenDataManager = (*Querier)(nil)
)

// GetPasswordResetTokenByToken fetches a password reset token from the database by its token.
func (q *Querier) GetPasswordResetTokenByToken(ctx context.Context, token string) (*types.PasswordResetToken, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if token == "" {
		return nil, ErrEmptyInputProvided
	}
	tracing.AttachToSpan(span, keys.PasswordResetTokenIDKey, token)

	result, err := q.generatedQuerier.GetPasswordResetToken(ctx, q.db, token)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, q.logger, span, "getting password reset token")
	}

	passwordResetToken := &types.PasswordResetToken{
		CreatedAt:     result.CreatedAt,
		ExpiresAt:     result.ExpiresAt,
		RedeemedAt:    database.TimePointerFromNullTime(result.RedeemedAt),
		LastUpdatedAt: database.TimePointerFromNullTime(result.LastUpdatedAt),
		ID:            result.ID,
		Token:         result.Token,
		BelongsToUser: result.BelongsToUser,
	}

	return passwordResetToken, nil
}

// CreatePasswordResetToken creates a password reset token in the database.
func (q *Querier) CreatePasswordResetToken(ctx context.Context, input *types.PasswordResetTokenDatabaseCreationInput) (*types.PasswordResetToken, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}
	logger := q.logger.WithValue(keys.PasswordResetTokenIDKey, input.ID)
	tracing.AttachToSpan(span, keys.PasswordResetTokenIDKey, input.ID)

	// create the password reset token.
	if err := q.generatedQuerier.CreatePasswordResetToken(ctx, q.db, &generated.CreatePasswordResetTokenParams{
		ID:            input.ID,
		Token:         input.Token,
		BelongsToUser: input.BelongsToUser,
	}); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "performing password reset token creation query")
	}

	x := &types.PasswordResetToken{
		ID:            input.ID,
		Token:         input.Token,
		ExpiresAt:     input.ExpiresAt,
		CreatedAt:     q.currentTime(),
		BelongsToUser: input.BelongsToUser,
	}

	logger.Info("password reset token created")

	return x, nil
}

// RedeemPasswordResetToken redeems a password reset token from the database by its ID.
func (q *Querier) RedeemPasswordResetToken(ctx context.Context, passwordResetTokenID string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if passwordResetTokenID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.PasswordResetTokenIDKey, passwordResetTokenID)
	tracing.AttachToSpan(span, keys.PasswordResetTokenIDKey, passwordResetTokenID)

	if err := q.generatedQuerier.RedeemPasswordResetToken(ctx, q.db, passwordResetTokenID); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "archiving password reset token")
	}

	logger.Info("password reset token archived")

	return nil
}
