package postgres

import (
	"context"
	"database/sql"
	"fmt"

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
	resourceTypeAccounts = "accounts"
)

var (
	_ types.AccountDataManager = (*Querier)(nil)
)

// GetAccount fetches a account from the database.
func (q *Querier) GetAccount(ctx context.Context, accountID string) (*types.Account, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" {
		return nil, ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	results, err := q.generatedQuerier.GetAccountByIDWithMemberships(ctx, q.db, accountID)
	if err != nil {
		return nil, observability.PrepareError(err, span, "executing accounts list retrieval query")
	}

	var account *types.Account
	for _, result := range results {
		if account == nil {
			account = &types.Account{
				CreatedAt:                  result.CreatedAt,
				SubscriptionPlanID:         database.StringPointerFromNullString(result.SubscriptionPlanID),
				LastUpdatedAt:              database.TimePointerFromNullTime(result.LastUpdatedAt),
				ArchivedAt:                 database.TimePointerFromNullTime(result.ArchivedAt),
				ContactPhone:               result.ContactPhone,
				BillingStatus:              result.BillingStatus,
				AddressLine1:               result.AddressLine1,
				AddressLine2:               result.AddressLine2,
				City:                       result.City,
				State:                      result.State,
				ZipCode:                    result.ZipCode,
				Country:                    result.Country,
				Latitude:                   database.Float64PointerFromNullString(result.Latitude),
				Longitude:                  database.Float64PointerFromNullString(result.Longitude),
				PaymentProcessorCustomerID: result.PaymentProcessorCustomerID,
				BelongsToUser:              result.BelongsToUser,
				ID:                         result.ID,
				Name:                       result.Name,
				WebhookEncryptionKey:       result.WebhookHmacSecret,
				Members:                    nil,
			}
		}

		account.Members = append(account.Members, &types.AccountUserMembershipWithUser{
			CreatedAt:     result.MembershipCreatedAt,
			LastUpdatedAt: database.TimePointerFromNullTime(result.MembershipLastUpdatedAt),
			ArchivedAt:    database.TimePointerFromNullTime(result.MembershipArchivedAt),
			ID:            result.MembershipID,
			BelongsToUser: &types.User{
				CreatedAt:                  result.UserCreatedAt,
				PasswordLastChangedAt:      database.TimePointerFromNullTime(result.UserPasswordLastChangedAt),
				LastUpdatedAt:              database.TimePointerFromNullTime(result.UserLastUpdatedAt),
				LastAcceptedTermsOfService: database.TimePointerFromNullTime(result.UserLastAcceptedTermsOfService),
				LastAcceptedPrivacyPolicy:  database.TimePointerFromNullTime(result.UserLastAcceptedPrivacyPolicy),
				TwoFactorSecretVerifiedAt:  database.TimePointerFromNullTime(result.UserTwoFactorSecretVerifiedAt),
				AvatarSrc:                  database.StringPointerFromNullString(result.UserAvatarSrc),
				Birthday:                   database.TimePointerFromNullTime(result.UserBirthday),
				ArchivedAt:                 database.TimePointerFromNullTime(result.UserArchivedAt),
				AccountStatusExplanation:   result.UserUserAccountStatusExplanation,
				ID:                         result.UserID,
				AccountStatus:              result.UserUserAccountStatus,
				Username:                   result.UserUsername,
				FirstName:                  result.UserFirstName,
				LastName:                   result.UserLastName,
				EmailAddress:               result.UserEmailAddress,
				EmailAddressVerifiedAt:     database.TimePointerFromNullTime(result.UserEmailAddressVerifiedAt),
				ServiceRole:                result.UserServiceRole,
				RequiresPasswordChange:     result.UserRequiresPasswordChange,
			},
			BelongsToAccount: result.MembershipBelongsToAccount,
			AccountRole:      result.MembershipAccountRole,
			DefaultAccount:   result.MembershipDefaultAccount,
		})
	}

	if account == nil {
		return nil, sql.ErrNoRows
	}

	return account, nil
}

// getAccountsForUser fetches a list of accounts from the database that meet a particular filter.
func (q *Querier) getAccountsForUser(ctx context.Context, querier database.SQLQueryExecutor, userID string, filter *types.QueryFilter) (x *types.QueryFilteredResult[types.Account], err error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if userID == "" {
		return nil, ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	logger = logger.WithValue(keys.UserIDKey, userID)

	if filter == nil {
		filter = types.DefaultQueryFilter()
	}
	logger = filter.AttachToLogger(logger)
	tracing.AttachQueryFilterToSpan(span, filter)

	x = &types.QueryFilteredResult[types.Account]{
		Pagination: filter.ToPagination(),
	}

	results, err := q.generatedQuerier.GetAccountsForUser(ctx, querier, &generated.GetAccountsForUserParams{
		BelongsToUser: userID,
		CreatedBefore: database.NullTimeFromTimePointer(filter.CreatedBefore),
		CreatedAfter:  database.NullTimeFromTimePointer(filter.CreatedAfter),
		UpdatedBefore: database.NullTimeFromTimePointer(filter.UpdatedBefore),
		UpdatedAfter:  database.NullTimeFromTimePointer(filter.UpdatedAfter),
		QueryOffset:   database.NullInt32FromUint16(filter.QueryOffset()),
		QueryLimit:    database.NullInt32FromUint8Pointer(filter.Limit),
	})
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "executing accounts list retrieval query")
	}

	for _, result := range results {
		x.Data = append(x.Data, &types.Account{
			CreatedAt:                  result.CreatedAt,
			SubscriptionPlanID:         database.StringPointerFromNullString(result.SubscriptionPlanID),
			LastUpdatedAt:              database.TimePointerFromNullTime(result.LastUpdatedAt),
			ArchivedAt:                 database.TimePointerFromNullTime(result.ArchivedAt),
			ContactPhone:               result.ContactPhone,
			BillingStatus:              result.BillingStatus,
			AddressLine1:               result.AddressLine1,
			AddressLine2:               result.AddressLine2,
			City:                       result.City,
			State:                      result.State,
			ZipCode:                    result.ZipCode,
			Country:                    result.Country,
			Latitude:                   database.Float64PointerFromNullString(result.Latitude),
			Longitude:                  database.Float64PointerFromNullString(result.Longitude),
			PaymentProcessorCustomerID: result.PaymentProcessorCustomerID,
			BelongsToUser:              result.BelongsToUser,
			ID:                         result.ID,
			Name:                       result.Name,
			Members:                    nil,
		})
		x.FilteredCount = uint64(result.FilteredCount)
		x.TotalCount = uint64(result.TotalCount)
	}

	return x, nil
}

// GetAccounts fetches a list of accounts from the database that meet a particular filter.
func (q *Querier) GetAccounts(ctx context.Context, userID string, filter *types.QueryFilter) (x *types.QueryFilteredResult[types.Account], err error) {
	return q.getAccountsForUser(ctx, q.db, userID, filter)
}

// CreateAccount creates a account in the database.
func (q *Querier) CreateAccount(ctx context.Context, input *types.AccountDatabaseCreationInput) (*types.Account, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	logger := q.logger.WithValue(keys.UserIDKey, input.BelongsToUser)

	// begin account creation transaction
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	// create the account.
	if writeErr := q.generatedQuerier.CreateAccount(ctx, tx, &generated.CreateAccountParams{
		City:              input.City,
		Name:              input.Name,
		BillingStatus:     types.UnpaidAccountBillingStatus,
		ContactPhone:      input.ContactPhone,
		AddressLine1:      input.AddressLine1,
		AddressLine2:      input.AddressLine2,
		ID:                input.ID,
		State:             input.State,
		ZipCode:           input.ZipCode,
		Country:           input.Country,
		BelongsToUser:     input.BelongsToUser,
		WebhookHmacSecret: input.WebhookEncryptionKey,
		Latitude:          database.NullStringFromFloat64Pointer(input.Latitude),
		Longitude:         database.NullStringFromFloat64Pointer(input.Longitude),
	}); writeErr != nil {
		q.rollbackTransaction(ctx, tx)
		return nil, observability.PrepareError(writeErr, span, "creating account")
	}

	account := &types.Account{
		ID:            input.ID,
		Name:          input.Name,
		BelongsToUser: input.BelongsToUser,
		BillingStatus: types.UnpaidAccountBillingStatus,
		ContactPhone:  input.ContactPhone,
		AddressLine1:  input.AddressLine1,
		AddressLine2:  input.AddressLine2,
		City:          input.City,
		State:         input.State,
		ZipCode:       input.ZipCode,
		Country:       input.Country,
		Latitude:      input.Latitude,
		Longitude:     input.Longitude,
		CreatedAt:     q.currentTime(),
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		BelongsToAccount: &account.ID,
		ID:               identifiers.New(),
		ResourceType:     resourceTypeAccounts,
		RelevantID:       account.ID,
		EventType:        types.AuditLogEventTypeCreated,
		BelongsToUser:    account.BelongsToUser,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return nil, observability.PrepareError(err, span, "creating audit log entry")
	}

	accountMembershipID := identifiers.New()
	if err = q.generatedQuerier.AddUserToAccount(ctx, tx, &generated.AddUserToAccountParams{
		ID:               accountMembershipID,
		BelongsToUser:    account.BelongsToUser,
		BelongsToAccount: account.ID,
		AccountRole:      authorization.AccountAdminRole.String(),
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return nil, observability.PrepareAndLogError(err, logger, span, "performing account membership creation query")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		BelongsToAccount: &account.ID,
		ID:               identifiers.New(),
		ResourceType:     resourceTypeAccountUserMemberships,
		RelevantID:       accountMembershipID,
		EventType:        types.AuditLogEventTypeCreated,
		BelongsToUser:    account.BelongsToUser,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return nil, observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	tracing.AttachToSpan(span, keys.AccountIDKey, account.ID)
	logger.Info("account created")

	return account, nil
}

// UpdateAccount updates a particular account. Note that UpdateAccount expects the provided input to have a valid ID.
func (q *Querier) UpdateAccount(ctx context.Context, updated *types.Account) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if updated == nil {
		return ErrNilInputProvided
	}
	logger := q.logger.WithValue(keys.AccountIDKey, updated.ID)
	tracing.AttachToSpan(span, keys.AccountIDKey, updated.ID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	account, err := q.GetAccount(ctx, updated.ID)
	if err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "fetching account")
	}

	if _, err = q.generatedQuerier.UpdateAccount(ctx, q.db, &generated.UpdateAccountParams{
		Name:          updated.Name,
		ContactPhone:  updated.ContactPhone,
		AddressLine1:  updated.AddressLine1,
		AddressLine2:  updated.AddressLine2,
		City:          updated.City,
		State:         updated.State,
		ZipCode:       updated.ZipCode,
		Country:       updated.Country,
		BelongsToUser: updated.BelongsToUser,
		ID:            updated.ID,
		Latitude:      database.NullStringFromFloat64Pointer(updated.Latitude),
		Longitude:     database.NullStringFromFloat64Pointer(updated.Longitude),
	}); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "updating account")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		BelongsToAccount: &updated.ID,
		ID:               identifiers.New(),
		ResourceType:     resourceTypeAccounts,
		RelevantID:       updated.ID,
		EventType:        types.AuditLogEventTypeUpdated,
		BelongsToUser:    account.BelongsToUser,
		Changes:          buildChangesForAccount(account, updated),
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("account updated")

	return nil
}

func buildChangesForAccount(account, updated *types.Account) map[string]types.ChangeLog {
	changes := map[string]types.ChangeLog{}

	if account.Name != updated.Name {
		changes["name"] = types.ChangeLog{
			OldValue: account.Name,
			NewValue: updated.Name,
		}
	}

	if account.ContactPhone != updated.ContactPhone {
		changes["contact_phone"] = types.ChangeLog{
			OldValue: account.ContactPhone,
			NewValue: updated.ContactPhone,
		}
	}

	if account.AddressLine1 != updated.AddressLine1 {
		changes["address_line_1"] = types.ChangeLog{
			OldValue: account.AddressLine1,
			NewValue: updated.AddressLine1,
		}
	}

	if account.AddressLine2 != updated.AddressLine2 {
		changes["address_line_2"] = types.ChangeLog{
			OldValue: account.AddressLine2,
			NewValue: updated.AddressLine2,
		}
	}

	if account.City != updated.City {
		changes["city"] = types.ChangeLog{
			OldValue: account.City,
			NewValue: updated.City,
		}
	}

	if account.State != updated.State {
		changes["state"] = types.ChangeLog{
			OldValue: account.State,
			NewValue: updated.State,
		}
	}

	if account.ZipCode != updated.ZipCode {
		changes["zip_code"] = types.ChangeLog{
			OldValue: account.ZipCode,
			NewValue: updated.ZipCode,
		}
	}

	if account.Country != updated.Country {
		changes["country"] = types.ChangeLog{
			OldValue: account.Country,
			NewValue: updated.Country,
		}
	}

	if account.Latitude != updated.Latitude {
		changes["latitude"] = types.ChangeLog{
			OldValue: fmt.Sprintf("%v", account.Latitude),
			NewValue: fmt.Sprintf("%v", updated.Latitude),
		}
	}

	if account.Longitude != updated.Longitude {
		changes["longitude"] = types.ChangeLog{
			OldValue: fmt.Sprintf("%v", account.Longitude),
			NewValue: fmt.Sprintf("%v", updated.Longitude),
		}
	}

	return changes
}

// ArchiveAccount archives a account from the database by its ID.
func (q *Querier) ArchiveAccount(ctx context.Context, accountID, userID string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if accountID == "" || userID == "" {
		return ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	logger = logger.WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)
	logger = logger.WithValue(keys.AccountIDKey, accountID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	if _, err = q.generatedQuerier.ArchiveAccount(ctx, q.db, &generated.ArchiveAccountParams{
		BelongsToUser: userID,
		ID:            accountID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "archiving account")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		BelongsToAccount: &accountID,
		ID:               identifiers.New(),
		ResourceType:     resourceTypeAccounts,
		RelevantID:       accountID,
		EventType:        types.AuditLogEventTypeCreated,
		BelongsToUser:    userID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("account archived")

	return nil
}
