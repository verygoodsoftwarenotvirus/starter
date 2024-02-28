package postgres

import (
	"context"
	"database/sql"

	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres/generated"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

var _ types.AdminUserDataManager = (*Querier)(nil)

// UpdateUserAccountStatus updates a user's account status.
func (q *Querier) UpdateUserAccountStatus(ctx context.Context, userID string, input *types.UserAccountStatusUpdateInput) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" {
		return ErrInvalidIDProvided
	}

	logger := q.logger.WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	rowsChanged, err := q.generatedQuerier.SetUserAccountStatus(ctx, q.db, &generated.SetUserAccountStatusParams{
		UserAccountStatus:            input.NewStatus,
		UserAccountStatusExplanation: input.Reason,
		ID:                           input.TargetUserID,
	})
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "user status update")
	}

	if rowsChanged == 0 {
		return sql.ErrNoRows
	}

	logger.Info("user account status updated")

	return nil
}
