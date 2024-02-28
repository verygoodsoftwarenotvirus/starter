package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres/generated"
	"github.com/verygoodsoftwarenotvirus/starter/internal/identifiers"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	resourceTypeAccountUserMemberships = "account_user_memberships"
)

var (
	_ types.AccountUserMembershipDataManager = (*Querier)(nil)
)

// BuildSessionContextDataForUser queries the database for the memberships of a user and constructs a SessionContextData struct from the results.
func (q *Querier) BuildSessionContextDataForUser(ctx context.Context, userID string) (*types.SessionContextData, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" {
		return nil, ErrInvalidIDProvided
	}

	logger := q.logger.WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	results, err := q.generatedQuerier.GetAccountUserMembershipsForUser(ctx, q.db, userID)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "fetching user's memberships from database")
	}

	accountRolesMap := map[string]authorization.AccountRolePermissionsChecker{}
	defaultAccountID := ""
	for _, result := range results {
		accountRolesMap[result.BelongsToAccount] = authorization.NewAccountRolePermissionChecker(result.AccountRole)
		if result.DefaultAccount {
			defaultAccountID = result.BelongsToAccount
		}
	}

	user, err := q.GetUser(ctx, userID)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "fetching user from database")
	}

	sessionCtxData := &types.SessionContextData{
		Requester: types.RequesterInfo{
			UserID:                   user.ID,
			Username:                 user.Username,
			EmailAddress:             user.EmailAddress,
			AccountStatus:            user.AccountStatus,
			AccountStatusExplanation: user.AccountStatusExplanation,
			ServicePermissions:       authorization.NewServiceRolePermissionChecker(user.ServiceRole),
		},
		AccountPermissions: accountRolesMap,
		ActiveAccountID:    defaultAccountID,
	}

	logger.Debug("fetched session context data for user")

	return sessionCtxData, nil
}

// GetDefaultAccountIDForUser retrieves the default account ID for a user.
func (q *Querier) GetDefaultAccountIDForUser(ctx context.Context, userID string) (string, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if userID == "" {
		return "", ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	logger = logger.WithValue(keys.UserIDKey, userID)

	id, err := q.generatedQuerier.GetDefaultAccountIDForUser(ctx, q.db, userID)
	if err != nil {
		return "", observability.PrepareAndLogError(err, logger, span, "fetching default account ID for user")
	}

	return id, nil
}

// markAccountAsUserDefault does a thing.
func (q *Querier) markAccountAsUserDefault(ctx context.Context, querier database.SQLQueryExecutor, userID, accountID string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" || accountID == "" {
		return ErrInvalidIDProvided
	}

	logger := q.logger.WithValues(map[string]any{
		keys.UserIDKey:    userID,
		keys.AccountIDKey: accountID,
	})

	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	if err = q.generatedQuerier.MarkAccountUserMembershipAsUserDefault(ctx, querier, &generated.MarkAccountUserMembershipAsUserDefaultParams{
		BelongsToUser:    userID,
		BelongsToAccount: accountID,
	}); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "assigning user default account")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		BelongsToAccount: &accountID,
		ID:               identifiers.New(),
		ResourceType:     resourceTypeAccountUserMemberships,
		EventType:        types.AuditLogEventTypeUpdated,
		BelongsToUser:    userID,
		Changes: map[string]types.ChangeLog{
			"default_account": {
				OldValue: "false",
				NewValue: "true",
			},
		},
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Debug("account marked as default")

	return nil
}

// MarkAccountAsUserDefault does a thing.
func (q *Querier) MarkAccountAsUserDefault(ctx context.Context, userID, accountID string) error {
	return q.markAccountAsUserDefault(ctx, q.db, userID, accountID)
}

// UserIsMemberOfAccount does a thing.
func (q *Querier) UserIsMemberOfAccount(ctx context.Context, userID, accountID string) (bool, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" || accountID == "" {
		return false, ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	result, err := q.generatedQuerier.UserIsAccountMember(ctx, q.db, &generated.UserIsAccountMemberParams{
		BelongsToAccount: accountID,
		BelongsToUser:    userID,
	})
	if err != nil {
		return false, observability.PrepareError(err, span, "performing user membership check query")
	}

	return result, nil
}

// ModifyUserPermissions does a thing.
func (q *Querier) ModifyUserPermissions(ctx context.Context, accountID, userID string, input *types.ModifyUserPermissionsInput) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" || userID == "" {
		return ErrInvalidIDProvided
	}

	if input == nil {
		return ErrNilInputProvided
	}

	logger := q.logger.WithValues(map[string]any{
		keys.AccountIDKey: accountID,
		keys.UserIDKey:    userID,
		"new_roles":       input.NewRole,
	})

	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	memberships, err := q.generatedQuerier.GetAccountUserMembershipsForUser(ctx, tx, userID)
	if err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "fetching user account memberships")
	}

	var existingRole string
	for _, membership := range memberships {
		if membership.BelongsToUser == userID && membership.BelongsToAccount == accountID {
			existingRole = membership.AccountRole
			break
		}
	}

	// modify the membership.
	if err = q.generatedQuerier.ModifyAccountUserPermissions(ctx, tx, &generated.ModifyAccountUserPermissionsParams{
		AccountRole:      input.NewRole,
		BelongsToAccount: accountID,
		BelongsToUser:    userID,
	}); err != nil && !errors.Is(err, sql.ErrNoRows) {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "modifying user account permissions")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		BelongsToAccount: &accountID,
		ID:               identifiers.New(),
		ResourceType:     resourceTypeAccountUserMemberships,
		EventType:        types.AuditLogEventTypeUpdated,
		BelongsToUser:    userID,
		Changes: map[string]types.ChangeLog{
			"account_role": {
				OldValue: existingRole,
				NewValue: input.NewRole,
			},
		},
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("user permissions modified")

	return nil
}

// TransferAccountOwnership does a thing.
func (q *Querier) TransferAccountOwnership(ctx context.Context, accountID string, input *types.AccountOwnershipTransferInput) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" {
		return ErrInvalidIDProvided
	}

	if input == nil {
		return ErrNilInputProvided
	}

	logger := q.logger.WithValues(map[string]any{
		keys.AccountIDKey: accountID,
		"current_owner":   input.CurrentOwner,
		"new_owner":       input.NewOwner,
	})

	tracing.AttachToSpan(span, keys.UserIDKey, input.NewOwner)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	// create the membership.
	if err = q.generatedQuerier.TransferAccountOwnership(ctx, tx, &generated.TransferAccountOwnershipParams{
		NewOwner:  input.NewOwner,
		OldOwner:  input.CurrentOwner,
		AccountID: accountID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "transferring account to new owner")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		BelongsToAccount: &accountID,
		ID:               identifiers.New(),
		ResourceType:     resourceTypeAccountUserMemberships,
		EventType:        types.AuditLogEventTypeUpdated,
		BelongsToUser:    input.NewOwner,
		Changes: map[string]types.ChangeLog{
			"belongs_to_user": {
				OldValue: input.CurrentOwner,
				NewValue: input.NewOwner,
			},
		},
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	isMember, err := q.UserIsMemberOfAccount(ctx, input.NewOwner, accountID)
	if err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "checking if user is member of account")
	}

	if !isMember {
		if err = q.addUserToAccount(ctx, tx, &types.AccountUserMembershipDatabaseCreationInput{
			ID:          identifiers.New(),
			Reason:      "transferred ownership",
			UserID:      input.NewOwner,
			AccountID:   accountID,
			AccountRole: "account_admin",
		}); err != nil {
			q.rollbackTransaction(ctx, tx)
			return observability.PrepareAndLogError(err, logger, span, "adding user to account")
		}
		// audit log created above
	}

	if err = q.removeUserFromAccount(ctx, tx, input.CurrentOwner, accountID); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "removing user from account")
	}

	// audit log created above

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("account transferred to new owner")

	return nil
}

// addUserToAccount does a thing.
func (q *Querier) addUserToAccount(ctx context.Context, querier database.SQLQueryExecutor, input *types.AccountUserMembershipDatabaseCreationInput) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return ErrNilInputProvided
	}

	logger := q.logger.WithValues(map[string]any{
		keys.UserIDKey:    input.UserID,
		keys.AccountIDKey: input.AccountID,
	})

	tracing.AttachToSpan(span, keys.UserIDKey, input.UserID)
	tracing.AttachToSpan(span, keys.AccountIDKey, input.AccountID)

	// create the membership.
	if err := q.generatedQuerier.AddUserToAccount(ctx, querier, &generated.AddUserToAccountParams{
		ID:               input.ID,
		BelongsToUser:    input.UserID,
		BelongsToAccount: input.AccountID,
		AccountRole:      input.AccountRole,
	}); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "performing user account membership creation query")
	}

	if _, err := q.createAuditLogEntry(ctx, querier, &types.AuditLogEntryDatabaseCreationInput{
		BelongsToAccount: &input.AccountID,
		ID:               identifiers.New(),
		ResourceType:     resourceTypeAccountUserMemberships,
		EventType:        types.AuditLogEventTypeCreated,
		BelongsToUser:    input.UserID,
	}); err != nil {
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	logger.Info("user added to account")

	return nil
}

// removeUserFromAccount removes a user's membership to a account.
func (q *Querier) removeUserFromAccount(ctx context.Context, querier database.SQLQueryExecutorAndTransactionManager, userID, accountID string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" || accountID == "" {
		return ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	logger := q.logger.WithValues(map[string]any{
		keys.UserIDKey:    userID,
		keys.AccountIDKey: accountID,
	})

	// remove the membership.
	if err := q.generatedQuerier.RemoveUserFromAccount(ctx, querier, &generated.RemoveUserFromAccountParams{
		BelongsToAccount: accountID,
		BelongsToUser:    userID,
	}); err != nil {
		q.rollbackTransaction(ctx, querier)
		return observability.PrepareAndLogError(err, logger, span, "removing user from account")
	}

	if _, err := q.createAuditLogEntry(ctx, querier, &types.AuditLogEntryDatabaseCreationInput{
		BelongsToAccount: &accountID,
		ID:               identifiers.New(),
		ResourceType:     resourceTypeAccountUserMemberships,
		EventType:        types.AuditLogEventTypeArchived,
		BelongsToUser:    userID,
	}); err != nil {
		q.rollbackTransaction(ctx, querier)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	remainingAccounts, err := q.getAccountsForUser(ctx, querier, userID, nil)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		q.rollbackTransaction(ctx, querier)
		return observability.PrepareError(err, span, "fetching remaining accounts")
	}

	if len(remainingAccounts.Data) < 1 {
		logger.Debug("user has no remaining accounts, creating a new one")
		if _, err = q.createAccountForUser(ctx, querier, false, "", userID); err != nil {
			return observability.PrepareAndLogError(err, logger, span, "creating account for new user")
		}
		return nil
	}

	account := remainingAccounts.Data[0]
	logger.WithValue("new_default_account", account.ID).Info("setting new default account")
	if err = q.markAccountAsUserDefault(ctx, querier, userID, account.ID); err != nil {
		q.rollbackTransaction(ctx, querier)
		return observability.PrepareAndLogError(err, logger, span, "marking account as default")
	}

	logger.Info("marked account as default")

	return nil
}

// RemoveUserFromAccount removes a user's membership to a account.
func (q *Querier) RemoveUserFromAccount(ctx context.Context, userID, accountID string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" {
		return ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	if accountID == "" {
		return ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	logger := q.logger.WithValues(map[string]any{
		keys.UserIDKey:    userID,
		keys.AccountIDKey: accountID,
	})

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareError(err, span, "beginning transaction")
	}

	if err = q.removeUserFromAccount(ctx, tx, userID, accountID); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "removing user from account")
	}

	// audit log entry created above

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	return nil
}
