package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres/generated"
	"github.com/verygoodsoftwarenotvirus/starter/internal/identifiers"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	resourceTypeUsers = "users"
)

var (
	_ types.UserDataManager = (*Querier)(nil)
)

// GetUser fetches a user.
func (q *Querier) GetUser(ctx context.Context, userID string) (*types.User, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" {
		return nil, ErrInvalidIDProvided
	}

	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	result, err := q.generatedQuerier.GetUserByID(ctx, q.db, userID)
	if err != nil {
		return nil, observability.PrepareError(err, span, "getting user with verified two factor")
	}

	u := &types.User{
		CreatedAt:                  result.CreatedAt,
		PasswordLastChangedAt:      database.TimePointerFromNullTime(result.PasswordLastChangedAt),
		LastUpdatedAt:              database.TimePointerFromNullTime(result.LastUpdatedAt),
		LastAcceptedTermsOfService: database.TimePointerFromNullTime(result.LastAcceptedTermsOfService),
		LastAcceptedPrivacyPolicy:  database.TimePointerFromNullTime(result.LastAcceptedPrivacyPolicy),
		TwoFactorSecretVerifiedAt:  database.TimePointerFromNullTime(result.TwoFactorSecretVerifiedAt),
		Birthday:                   database.TimePointerFromNullTime(result.Birthday),
		ArchivedAt:                 database.TimePointerFromNullTime(result.ArchivedAt),
		AccountStatusExplanation:   result.UserAccountStatusExplanation,
		TwoFactorSecret:            result.TwoFactorSecret,
		HashedPassword:             result.HashedPassword,
		ID:                         result.ID,
		AccountStatus:              result.UserAccountStatus,
		Username:                   result.Username,
		FirstName:                  result.FirstName,
		LastName:                   result.LastName,
		EmailAddress:               result.EmailAddress,
		EmailAddressVerifiedAt:     database.TimePointerFromNullTime(result.EmailAddressVerifiedAt),
		AvatarSrc:                  database.StringPointerFromNullString(result.AvatarSrc),
		ServiceRole:                result.ServiceRole,
		RequiresPasswordChange:     result.RequiresPasswordChange,
	}

	return u, nil
}

// GetUserWithUnverifiedTwoFactorSecret fetches a user with an unverified 2FA secret.
func (q *Querier) GetUserWithUnverifiedTwoFactorSecret(ctx context.Context, userID string) (*types.User, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" {
		return nil, ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	result, err := q.generatedQuerier.GetUserWithUnverifiedTwoFactor(ctx, q.db, userID)
	if err != nil {
		return nil, observability.PrepareError(err, span, "getting user with verified two factor")
	}

	u := &types.User{
		CreatedAt:                  result.CreatedAt,
		PasswordLastChangedAt:      database.TimePointerFromNullTime(result.PasswordLastChangedAt),
		LastUpdatedAt:              database.TimePointerFromNullTime(result.LastUpdatedAt),
		LastAcceptedTermsOfService: database.TimePointerFromNullTime(result.LastAcceptedTermsOfService),
		LastAcceptedPrivacyPolicy:  database.TimePointerFromNullTime(result.LastAcceptedPrivacyPolicy),
		TwoFactorSecretVerifiedAt:  database.TimePointerFromNullTime(result.TwoFactorSecretVerifiedAt),
		Birthday:                   database.TimePointerFromNullTime(result.Birthday),
		ArchivedAt:                 database.TimePointerFromNullTime(result.ArchivedAt),
		AccountStatusExplanation:   result.UserAccountStatusExplanation,
		TwoFactorSecret:            result.TwoFactorSecret,
		HashedPassword:             result.HashedPassword,
		ID:                         result.ID,
		AccountStatus:              result.UserAccountStatus,
		Username:                   result.Username,
		FirstName:                  result.FirstName,
		LastName:                   result.LastName,
		EmailAddress:               result.EmailAddress,
		EmailAddressVerifiedAt:     database.TimePointerFromNullTime(result.EmailAddressVerifiedAt),
		AvatarSrc:                  database.StringPointerFromNullString(result.AvatarSrc),
		ServiceRole:                result.ServiceRole,
		RequiresPasswordChange:     result.RequiresPasswordChange,
	}

	return u, nil
}

// GetUserByUsername fetches a user by their username.
func (q *Querier) GetUserByUsername(ctx context.Context, username string) (*types.User, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if username == "" {
		return nil, ErrEmptyInputProvided
	}
	tracing.AttachToSpan(span, keys.UsernameKey, username)

	result, err := q.generatedQuerier.GetUserByUsername(ctx, q.db, username)
	if err != nil {
		return nil, observability.PrepareError(err, span, "getting user by username")
	}

	u := &types.User{
		CreatedAt:                  result.CreatedAt,
		PasswordLastChangedAt:      database.TimePointerFromNullTime(result.PasswordLastChangedAt),
		LastUpdatedAt:              database.TimePointerFromNullTime(result.LastUpdatedAt),
		LastAcceptedTermsOfService: database.TimePointerFromNullTime(result.LastAcceptedTermsOfService),
		LastAcceptedPrivacyPolicy:  database.TimePointerFromNullTime(result.LastAcceptedPrivacyPolicy),
		TwoFactorSecretVerifiedAt:  database.TimePointerFromNullTime(result.TwoFactorSecretVerifiedAt),
		Birthday:                   database.TimePointerFromNullTime(result.Birthday),
		ArchivedAt:                 database.TimePointerFromNullTime(result.ArchivedAt),
		AccountStatusExplanation:   result.UserAccountStatusExplanation,
		TwoFactorSecret:            result.TwoFactorSecret,
		HashedPassword:             result.HashedPassword,
		ID:                         result.ID,
		AccountStatus:              result.UserAccountStatus,
		Username:                   result.Username,
		FirstName:                  result.FirstName,
		LastName:                   result.LastName,
		EmailAddress:               result.EmailAddress,
		EmailAddressVerifiedAt:     database.TimePointerFromNullTime(result.EmailAddressVerifiedAt),
		AvatarSrc:                  database.StringPointerFromNullString(result.AvatarSrc),
		ServiceRole:                result.ServiceRole,
		RequiresPasswordChange:     result.RequiresPasswordChange,
	}

	return u, nil
}

// GetAdminUserByUsername fetches a user by their username.
func (q *Querier) GetAdminUserByUsername(ctx context.Context, username string) (*types.User, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if username == "" {
		return nil, ErrEmptyInputProvided
	}
	tracing.AttachToSpan(span, keys.UsernameKey, username)

	result, err := q.generatedQuerier.GetAdminUserByUsername(ctx, q.db, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, observability.PrepareError(err, span, "getting admin user by username")
	}

	u := &types.User{
		CreatedAt:                  result.CreatedAt,
		PasswordLastChangedAt:      database.TimePointerFromNullTime(result.PasswordLastChangedAt),
		LastUpdatedAt:              database.TimePointerFromNullTime(result.LastUpdatedAt),
		LastAcceptedTermsOfService: database.TimePointerFromNullTime(result.LastAcceptedTermsOfService),
		LastAcceptedPrivacyPolicy:  database.TimePointerFromNullTime(result.LastAcceptedPrivacyPolicy),
		TwoFactorSecretVerifiedAt:  database.TimePointerFromNullTime(result.TwoFactorSecretVerifiedAt),
		Birthday:                   database.TimePointerFromNullTime(result.Birthday),
		ArchivedAt:                 database.TimePointerFromNullTime(result.ArchivedAt),
		AccountStatusExplanation:   result.UserAccountStatusExplanation,
		TwoFactorSecret:            result.TwoFactorSecret,
		HashedPassword:             result.HashedPassword,
		ID:                         result.ID,
		AccountStatus:              result.UserAccountStatus,
		Username:                   result.Username,
		FirstName:                  result.FirstName,
		LastName:                   result.LastName,
		EmailAddress:               result.EmailAddress,
		EmailAddressVerifiedAt:     database.TimePointerFromNullTime(result.EmailAddressVerifiedAt),
		AvatarSrc:                  database.StringPointerFromNullString(result.AvatarSrc),
		ServiceRole:                result.ServiceRole,
		RequiresPasswordChange:     result.RequiresPasswordChange,
	}

	return u, nil
}

// GetUserByEmail fetches a user by their email.
func (q *Querier) GetUserByEmail(ctx context.Context, email string) (*types.User, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if email == "" {
		return nil, ErrEmptyInputProvided
	}
	tracing.AttachToSpan(span, keys.UserEmailAddressKey, email)

	result, err := q.generatedQuerier.GetUserByEmail(ctx, q.db, email)
	if err != nil {
		return nil, observability.PrepareError(err, span, "getting user by email")
	}

	u := &types.User{
		CreatedAt:                  result.CreatedAt,
		PasswordLastChangedAt:      database.TimePointerFromNullTime(result.PasswordLastChangedAt),
		LastUpdatedAt:              database.TimePointerFromNullTime(result.LastUpdatedAt),
		LastAcceptedTermsOfService: database.TimePointerFromNullTime(result.LastAcceptedTermsOfService),
		LastAcceptedPrivacyPolicy:  database.TimePointerFromNullTime(result.LastAcceptedPrivacyPolicy),
		TwoFactorSecretVerifiedAt:  database.TimePointerFromNullTime(result.TwoFactorSecretVerifiedAt),
		Birthday:                   database.TimePointerFromNullTime(result.Birthday),
		ArchivedAt:                 database.TimePointerFromNullTime(result.ArchivedAt),
		AccountStatusExplanation:   result.UserAccountStatusExplanation,
		TwoFactorSecret:            result.TwoFactorSecret,
		HashedPassword:             result.HashedPassword,
		ID:                         result.ID,
		AccountStatus:              result.UserAccountStatus,
		Username:                   result.Username,
		FirstName:                  result.FirstName,
		LastName:                   result.LastName,
		EmailAddress:               result.EmailAddress,
		EmailAddressVerifiedAt:     database.TimePointerFromNullTime(result.EmailAddressVerifiedAt),
		AvatarSrc:                  database.StringPointerFromNullString(result.AvatarSrc),
		ServiceRole:                result.ServiceRole,
		RequiresPasswordChange:     result.RequiresPasswordChange,
	}

	return u, nil
}

// SearchForUsersByUsername fetches a list of users whose usernames begin with a given query.
func (q *Querier) SearchForUsersByUsername(ctx context.Context, usernameQuery string) ([]*types.User, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if usernameQuery == "" {
		return []*types.User{}, ErrEmptyInputProvided
	}
	tracing.AttachToSpan(span, keys.SearchQueryKey, usernameQuery)

	results, err := q.generatedQuerier.SearchUsersByUsername(ctx, q.db, usernameQuery)
	if err != nil {
		return nil, observability.PrepareError(err, span, "querying database for users")
	}

	users := make([]*types.User, len(results))
	for i, result := range results {
		users[i] = &types.User{
			CreatedAt:                  result.CreatedAt,
			PasswordLastChangedAt:      database.TimePointerFromNullTime(result.PasswordLastChangedAt),
			LastUpdatedAt:              database.TimePointerFromNullTime(result.LastUpdatedAt),
			LastAcceptedTermsOfService: database.TimePointerFromNullTime(result.LastAcceptedTermsOfService),
			LastAcceptedPrivacyPolicy:  database.TimePointerFromNullTime(result.LastAcceptedPrivacyPolicy),
			TwoFactorSecretVerifiedAt:  database.TimePointerFromNullTime(result.TwoFactorSecretVerifiedAt),
			Birthday:                   database.TimePointerFromNullTime(result.Birthday),
			ArchivedAt:                 database.TimePointerFromNullTime(result.ArchivedAt),
			AccountStatusExplanation:   result.UserAccountStatusExplanation,
			TwoFactorSecret:            result.TwoFactorSecret,
			HashedPassword:             result.HashedPassword,
			ID:                         result.ID,
			AccountStatus:              result.UserAccountStatus,
			Username:                   result.Username,
			FirstName:                  result.FirstName,
			LastName:                   result.LastName,
			EmailAddress:               result.EmailAddress,
			EmailAddressVerifiedAt:     database.TimePointerFromNullTime(result.EmailAddressVerifiedAt),
			AvatarSrc:                  database.StringPointerFromNullString(result.AvatarSrc),
			ServiceRole:                result.ServiceRole,
			RequiresPasswordChange:     result.RequiresPasswordChange,
		}
	}

	if len(users) == 0 {
		return nil, sql.ErrNoRows
	}

	return users, nil
}

// GetUsers fetches a list of users from the database that meet a particular filter.
func (q *Querier) GetUsers(ctx context.Context, filter *types.QueryFilter) (x *types.QueryFilteredResult[types.User], err error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if filter == nil {
		filter = types.DefaultQueryFilter()
	}
	tracing.AttachQueryFilterToSpan(span, filter)
	filter.AttachToLogger(logger)

	x = &types.QueryFilteredResult[types.User]{
		Pagination: filter.ToPagination(),
	}

	results, err := q.generatedQuerier.GetUsers(ctx, q.db, &generated.GetUsersParams{
		CreatedBefore: database.NullTimeFromTimePointer(filter.CreatedBefore),
		CreatedAfter:  database.NullTimeFromTimePointer(filter.CreatedAfter),
		UpdatedBefore: database.NullTimeFromTimePointer(filter.UpdatedBefore),
		UpdatedAfter:  database.NullTimeFromTimePointer(filter.UpdatedAfter),
		QueryOffset:   database.NullInt32FromUint16(filter.QueryOffset()),
		QueryLimit:    database.NullInt32FromUint8Pointer(filter.Limit),
	})
	if err != nil {
		return nil, observability.PrepareError(err, span, "scanning user")
	}

	for _, result := range results {
		u := &types.User{
			CreatedAt:                  result.CreatedAt,
			PasswordLastChangedAt:      database.TimePointerFromNullTime(result.PasswordLastChangedAt),
			LastUpdatedAt:              database.TimePointerFromNullTime(result.LastUpdatedAt),
			LastAcceptedTermsOfService: database.TimePointerFromNullTime(result.LastAcceptedTermsOfService),
			LastAcceptedPrivacyPolicy:  database.TimePointerFromNullTime(result.LastAcceptedPrivacyPolicy),
			TwoFactorSecretVerifiedAt:  database.TimePointerFromNullTime(result.TwoFactorSecretVerifiedAt),
			Birthday:                   database.TimePointerFromNullTime(result.Birthday),
			ArchivedAt:                 database.TimePointerFromNullTime(result.ArchivedAt),
			AccountStatusExplanation:   result.UserAccountStatusExplanation,
			TwoFactorSecret:            result.TwoFactorSecret,
			HashedPassword:             result.HashedPassword,
			ID:                         result.ID,
			AccountStatus:              result.UserAccountStatus,
			Username:                   result.Username,
			FirstName:                  result.FirstName,
			LastName:                   result.LastName,
			EmailAddress:               result.EmailAddress,
			EmailAddressVerifiedAt:     database.TimePointerFromNullTime(result.EmailAddressVerifiedAt),
			AvatarSrc:                  database.StringPointerFromNullString(result.AvatarSrc),
			ServiceRole:                result.ServiceRole,
			RequiresPasswordChange:     result.RequiresPasswordChange,
		}

		x.Data = append(x.Data, u)
		x.FilteredCount = uint64(result.FilteredCount)
		x.TotalCount = uint64(result.TotalCount)
	}

	return x, nil
}

// GetUserIDsThatNeedSearchIndexing fetches a list of valid vessels from the database that meet a particular filter.
func (q *Querier) GetUserIDsThatNeedSearchIndexing(ctx context.Context) ([]string, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	results, err := q.generatedQuerier.GetUserIDsNeedingIndexing(ctx, q.db)
	if err != nil {
		return nil, observability.PrepareError(err, span, "executing users list retrieval query")
	}

	return results, nil
}

// MarkUserAsIndexed updates a particular user's last_indexed_at value.
func (q *Querier) MarkUserAsIndexed(ctx context.Context, userID string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if userID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	if _, err := q.generatedQuerier.UpdateUserLastIndexedAt(ctx, q.db, userID); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "marking user as indexed")
	}

	logger.Info("user marked as indexed")

	return nil
}

// CreateUser creates a user. TODO: this should return a account as well.
func (q *Querier) CreateUser(ctx context.Context, input *types.UserDatabaseCreationInput) (*types.User, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	tracing.AttachToSpan(span, keys.UsernameKey, input.Username)
	logger := q.logger.WithValues(map[string]any{
		keys.UsernameKey:               input.Username,
		keys.UserEmailAddressKey:       input.EmailAddress,
		keys.AccountInvitationTokenKey: input.InvitationToken,
		"destination_account":          input.DestinationAccountID,
	})

	// begin user creation transaction
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, observability.PrepareError(err, span, "beginning transaction")
	}

	token, err := q.secretGenerator.GenerateBase64EncodedString(ctx, 32)
	if err != nil {
		q.rollbackTransaction(ctx, tx)
		return nil, observability.PrepareError(err, span, "generating email verification token")
	}

	if err = q.generatedQuerier.CreateUser(ctx, tx, &generated.CreateUserParams{
		ID:                            input.ID,
		FirstName:                     input.FirstName,
		LastName:                      input.LastName,
		Username:                      input.Username,
		EmailAddress:                  input.EmailAddress,
		HashedPassword:                input.HashedPassword,
		TwoFactorSecret:               input.TwoFactorSecret,
		AvatarSrc:                     database.NullStringFromStringPointer(input.AvatarSrc),
		UserAccountStatus:             string(types.UnverifiedAccountStatus),
		Birthday:                      database.NullTimeFromTimePointer(input.Birthday),
		ServiceRole:                   authorization.ServiceUserRole.String(),
		EmailAddressVerificationToken: database.NullStringFromString(token),
	}); err != nil {
		q.rollbackTransaction(ctx, tx)

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == postgresDuplicateEntryErrorCode {
				return nil, database.ErrUserAlreadyExists
			}
		}

		return nil, observability.PrepareError(err, span, "creating user")
	}

	hasValidInvite := input.InvitationToken != "" && input.DestinationAccountID != ""

	user := &types.User{
		ID:              input.ID,
		FirstName:       input.FirstName,
		LastName:        input.LastName,
		Username:        input.Username,
		EmailAddress:    input.EmailAddress,
		HashedPassword:  input.HashedPassword,
		TwoFactorSecret: input.TwoFactorSecret,
		AccountStatus:   string(types.UnverifiedAccountStatus),
		Birthday:        input.Birthday,
		ServiceRole:     authorization.ServiceUserRole.String(),
		CreatedAt:       q.currentTime(),
	}
	logger = logger.WithValue(keys.UserIDKey, user.ID)
	tracing.AttachToSpan(span, keys.UserIDKey, user.ID)

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUsers,
		RelevantID:    input.ID,
		EventType:     types.AuditLogEventTypeCreated,
		BelongsToUser: input.ID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return nil, observability.PrepareError(err, span, "creating audit log entry")
	}

	if strings.TrimSpace(input.AccountName) == "" {
		input.AccountName = fmt.Sprintf("%s's cool account", input.Username)
	}

	account, err := q.createAccountForUser(ctx, tx, hasValidInvite, input.AccountName, user.ID)
	if err != nil {
		q.rollbackTransaction(ctx, tx)
		return nil, observability.PrepareAndLogError(err, logger, span, "creating account for new user")
	}
	logger = logger.WithValue(keys.AccountIDKey, account.ID)
	logger.Debug("account created")

	if hasValidInvite {
		if err = q.acceptInvitationForUser(ctx, tx, input); err != nil {
			q.rollbackTransaction(ctx, tx)
			return nil, observability.PrepareAndLogError(err, logger, span, "accepting account invitation")
		}
		logger.Debug("accepted invitation and joined account for user")
	}

	if err = q.attachInvitationsToUser(ctx, tx, user.EmailAddress, user.ID); err != nil {
		q.rollbackTransaction(ctx, tx)
		logger = logger.WithValue("email_address", user.EmailAddress).WithValue("user_id", user.ID)
		return nil, observability.PrepareAndLogError(err, logger, span, "attaching existing invitations to new user")
	}

	if err = tx.Commit(); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Debug("user and account created")

	return user, nil
}

func (q *Querier) createAccountForUser(ctx context.Context, querier database.SQLQueryExecutorAndTransactionManager, hasValidInvite bool, accountName, userID string) (*types.Account, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	// standard registration: we need to create the account
	accountID := identifiers.New()
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	hn := accountName
	if accountName == "" {
		hn = fmt.Sprintf("%s_default", userID)
	}

	accountCreationInput := &types.AccountDatabaseCreationInput{
		ID:            accountID,
		Name:          hn,
		BelongsToUser: userID,
	}

	// create the account.
	if err := q.generatedQuerier.CreateAccount(ctx, querier, &generated.CreateAccountParams{
		City:          accountCreationInput.City,
		Name:          accountCreationInput.Name,
		BillingStatus: types.UnpaidAccountBillingStatus,
		ContactPhone:  accountCreationInput.ContactPhone,
		AddressLine1:  accountCreationInput.AddressLine1,
		AddressLine2:  accountCreationInput.AddressLine2,
		ID:            accountCreationInput.ID,
		State:         accountCreationInput.State,
		ZipCode:       accountCreationInput.ZipCode,
		Country:       accountCreationInput.Country,
		BelongsToUser: accountCreationInput.BelongsToUser,
		Latitude:      database.NullStringFromFloat64Pointer(accountCreationInput.Latitude),
		Longitude:     database.NullStringFromFloat64Pointer(accountCreationInput.Longitude),
	}); err != nil {
		q.rollbackTransaction(ctx, querier)
		return nil, observability.PrepareError(err, span, "creating account")
	}

	if _, err := q.createAuditLogEntry(ctx, querier, &types.AuditLogEntryDatabaseCreationInput{
		BelongsToAccount: &accountCreationInput.ID,
		ID:               identifiers.New(),
		ResourceType:     resourceTypeAccounts,
		RelevantID:       accountCreationInput.ID,
		EventType:        types.AuditLogEventTypeCreated,
		BelongsToUser:    accountCreationInput.BelongsToUser,
	}); err != nil {
		q.rollbackTransaction(ctx, querier)
		return nil, observability.PrepareError(err, span, "creating audit log entry")
	}

	accountMembershipID := identifiers.New()
	if err := q.generatedQuerier.CreateAccountUserMembershipForNewUser(ctx, querier, &generated.CreateAccountUserMembershipForNewUserParams{
		ID:               accountMembershipID,
		BelongsToUser:    userID,
		BelongsToAccount: accountID,
		AccountRole:      authorization.AccountAdminRole.String(),
		DefaultAccount:   !hasValidInvite,
	}); err != nil {
		q.rollbackTransaction(ctx, querier)
		return nil, observability.PrepareError(err, span, "writing account user membership")
	}

	if _, err := q.createAuditLogEntry(ctx, querier, &types.AuditLogEntryDatabaseCreationInput{
		BelongsToAccount: &accountCreationInput.ID,
		ID:               identifiers.New(),
		ResourceType:     resourceTypeAccountUserMemberships,
		RelevantID:       accountMembershipID,
		EventType:        types.AuditLogEventTypeCreated,
		BelongsToUser:    accountCreationInput.BelongsToUser,
	}); err != nil {
		q.rollbackTransaction(ctx, querier)
		return nil, observability.PrepareError(err, span, "creating audit log entry")
	}

	account := &types.Account{
		CreatedAt:            q.currentTime(),
		Longitude:            accountCreationInput.Longitude,
		Latitude:             accountCreationInput.Latitude,
		State:                accountCreationInput.State,
		ContactPhone:         accountCreationInput.ContactPhone,
		City:                 accountCreationInput.City,
		AddressLine1:         accountCreationInput.AddressLine1,
		ZipCode:              accountCreationInput.ZipCode,
		Country:              accountCreationInput.Country,
		BillingStatus:        types.UnpaidAccountBillingStatus,
		AddressLine2:         accountCreationInput.AddressLine2,
		BelongsToUser:        accountCreationInput.BelongsToUser,
		ID:                   accountCreationInput.ID,
		Name:                 accountCreationInput.Name,
		WebhookEncryptionKey: accountCreationInput.WebhookEncryptionKey,
		Members:              nil,
	}

	return account, nil
}

// UpdateUserUsername updates a user's username.
func (q *Querier) UpdateUserUsername(ctx context.Context, userID, newUsername string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if userID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	if newUsername == "" {
		return ErrEmptyInputProvided
	}
	logger = logger.WithValue(keys.UsernameKey, newUsername)
	tracing.AttachToSpan(span, keys.UsernameKey, newUsername)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	user, err := q.GetUser(ctx, userID)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "fetching user")
	}

	if _, err = q.generatedQuerier.UpdateUserUsername(ctx, tx, &generated.UpdateUserUsernameParams{
		Username: newUsername,
		ID:       userID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "updating username")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUsers,
		RelevantID:    userID,
		EventType:     types.AuditLogEventTypeUpdated,
		BelongsToUser: userID,
		Changes: map[string]types.ChangeLog{
			"username": {
				OldValue: user.Username,
				NewValue: newUsername,
			},
		},
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("username updated")

	return nil
}

// UpdateUserEmailAddress updates a user's username.
func (q *Querier) UpdateUserEmailAddress(ctx context.Context, userID, newEmailAddress string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" {
		return ErrInvalidIDProvided
	}
	logger := q.logger.WithValue(keys.UserEmailAddressKey, newEmailAddress).WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	if newEmailAddress == "" {
		return ErrEmptyInputProvided
	}
	tracing.AttachToSpan(span, keys.UserEmailAddressKey, newEmailAddress)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	user, err := q.GetUser(ctx, userID)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "fetching user")
	}

	if _, err = q.generatedQuerier.UpdateUserEmailAddress(ctx, tx, &generated.UpdateUserEmailAddressParams{
		EmailAddress: newEmailAddress,
		ID:           userID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "updating user email address")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUsers,
		RelevantID:    userID,
		EventType:     types.AuditLogEventTypeUpdated,
		BelongsToUser: userID,
		Changes: map[string]types.ChangeLog{
			"email_address": {
				OldValue: user.EmailAddress,
				NewValue: newEmailAddress,
			},
		},
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("user email address updated")

	return nil
}

// UpdateUserDetails updates a user's username.
func (q *Querier) UpdateUserDetails(ctx context.Context, userID string, input *types.UserDetailsDatabaseUpdateInput) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return ErrEmptyInputProvided
	}

	if userID == "" {
		return ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	logger := q.logger.WithValue(keys.UserIDKey, userID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	user, err := q.GetUser(ctx, userID)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "fetching user")
	}

	if _, err = q.generatedQuerier.UpdateUserDetails(ctx, tx, &generated.UpdateUserDetailsParams{
		FirstName: input.FirstName,
		LastName:  input.LastName,
		Birthday:  database.NullTimeFromTime(input.Birthday),
		ID:        userID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "updating user details")
	}

	changes := map[string]types.ChangeLog{}
	if input.FirstName != user.FirstName {
		changes["first_name"] = types.ChangeLog{NewValue: input.FirstName, OldValue: user.FirstName}
	}

	if input.LastName != user.LastName {
		changes["last_name"] = types.ChangeLog{NewValue: input.LastName, OldValue: user.LastName}
	}

	if input.Birthday.Format(time.Kitchen) != user.Birthday.Format(time.Kitchen) {
		changes["birthday"] = types.ChangeLog{NewValue: input.Birthday.Format(time.Kitchen), OldValue: user.Birthday.Format(time.Kitchen)}
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUsers,
		RelevantID:    userID,
		EventType:     types.AuditLogEventTypeUpdated,
		BelongsToUser: userID,
		Changes:       changes,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("user details updated")

	return nil
}

// UpdateUserAvatar updates a user's avatar source.
func (q *Querier) UpdateUserAvatar(ctx context.Context, userID, newAvatarSrc string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if newAvatarSrc == "" {
		return ErrEmptyInputProvided
	}

	if userID == "" {
		return ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	logger := q.logger.WithValue(keys.UserIDKey, userID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	if _, err = q.generatedQuerier.UpdateUserAvatarSrc(ctx, tx, &generated.UpdateUserAvatarSrcParams{
		AvatarSrc: database.NullStringFromString(newAvatarSrc),
		ID:        userID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "updating user avatar")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUsers,
		RelevantID:    userID,
		EventType:     types.AuditLogEventTypeUpdated,
		BelongsToUser: userID,
		Changes: map[string]types.ChangeLog{
			"avatar": {},
		},
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("user avatar updated")

	return nil
}

// UpdateUserPassword updates a user's passwords hash in the database.
func (q *Querier) UpdateUserPassword(ctx context.Context, userID, newHash string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if newHash == "" {
		return ErrEmptyInputProvided
	}

	if userID == "" {
		return ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	logger := q.logger.WithValue(keys.UserIDKey, userID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	if _, err = q.generatedQuerier.UpdateUserPassword(ctx, tx, &generated.UpdateUserPasswordParams{
		HashedPassword: newHash,
		ID:             userID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "updating user password")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUsers,
		RelevantID:    userID,
		EventType:     types.AuditLogEventTypeUpdated,
		BelongsToUser: userID,
		Changes: map[string]types.ChangeLog{
			"password": {},
		},
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("user password updated")

	return nil
}

// UpdateUserTwoFactorSecret marks a user's two factor secret as validated.
func (q *Querier) UpdateUserTwoFactorSecret(ctx context.Context, userID, newSecret string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if newSecret == "" {
		return ErrEmptyInputProvided
	}

	if userID == "" {
		return ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	logger := q.logger.WithValue(keys.UserIDKey, userID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	if _, err = q.generatedQuerier.UpdateUserTwoFactorSecret(ctx, tx, &generated.UpdateUserTwoFactorSecretParams{
		TwoFactorSecret: newSecret,
		ID:              userID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "updating user 2FA secret")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUsers,
		RelevantID:    userID,
		EventType:     types.AuditLogEventTypeUpdated,
		BelongsToUser: userID,
		Changes: map[string]types.ChangeLog{
			"two_factor_secret": {},
		},
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("user two factor secret updated")

	return nil
}

// MarkUserTwoFactorSecretAsVerified marks a user's two factor secret as validated.
func (q *Querier) MarkUserTwoFactorSecretAsVerified(ctx context.Context, userID string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" {
		return ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	logger := q.logger.WithValue(keys.UserIDKey, userID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	if err = q.generatedQuerier.MarkTwoFactorSecretAsVerified(ctx, tx, userID); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "writing verified two factor status to database")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUsers,
		RelevantID:    userID,
		EventType:     types.AuditLogEventTypeUpdated,
		BelongsToUser: userID,
		Changes: map[string]types.ChangeLog{
			"two_factor_secret": {
				OldValue: "unverified",
				NewValue: "verified",
			},
		},
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("user two factor secret verified")

	return nil
}

// MarkUserTwoFactorSecretAsUnverified marks a user's two factor secret as unverified.
func (q *Querier) MarkUserTwoFactorSecretAsUnverified(ctx context.Context, userID, newSecret string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if newSecret == "" {
		return ErrEmptyInputProvided
	}

	if userID == "" {
		return ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	logger := q.logger.WithValue(keys.UserIDKey, userID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	if err = q.generatedQuerier.MarkTwoFactorSecretAsUnverified(ctx, q.db, &generated.MarkTwoFactorSecretAsUnverifiedParams{
		TwoFactorSecret: newSecret,
		ID:              userID,
	}); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "writing verified two factor status to database")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUsers,
		RelevantID:    userID,
		EventType:     types.AuditLogEventTypeArchived,
		BelongsToUser: userID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUsers,
		RelevantID:    userID,
		EventType:     types.AuditLogEventTypeCreated,
		BelongsToUser: userID,
		Changes: map[string]types.ChangeLog{
			"two_factor_secret": {
				OldValue: "verified",
				NewValue: "unverified",
			},
		},
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("user two factor secret unverified")

	return nil
}

// ArchiveUser archives a user.
func (q *Querier) ArchiveUser(ctx context.Context, userID string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" {
		return ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	logger := q.logger.WithValue(keys.UserIDKey, userID)

	// begin archive user transaction
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	changed, err := q.generatedQuerier.ArchiveUser(ctx, tx, userID)
	if err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "archiving user")
	}

	if changed == 0 {
		return sql.ErrNoRows
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUsers,
		RelevantID:    userID,
		EventType:     types.AuditLogEventTypeArchived,
		BelongsToUser: userID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if _, err = q.generatedQuerier.ArchiveUserMemberships(ctx, tx, userID); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "archiving user account memberships")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("user archived")

	return nil
}

func (q *Querier) GetEmailAddressVerificationTokenForUser(ctx context.Context, userID string) (string, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" {
		return "", ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	result, err := q.generatedQuerier.GetEmailVerificationTokenByUserID(ctx, q.db, userID)
	if err != nil {
		return "", observability.PrepareError(err, span, "getting user by email address verification token")
	}

	return result.String, nil
}

func (q *Querier) GetUserByEmailAddressVerificationToken(ctx context.Context, token string) (*types.User, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if token == "" {
		return nil, ErrEmptyInputProvided
	}

	result, err := q.generatedQuerier.GetUserByEmailAddressVerificationToken(ctx, q.db, database.NullStringFromString(token))
	if err != nil {
		return nil, observability.PrepareError(err, span, "getting user by email address verification token")
	}

	u := &types.User{
		CreatedAt:                  result.CreatedAt,
		PasswordLastChangedAt:      database.TimePointerFromNullTime(result.PasswordLastChangedAt),
		LastUpdatedAt:              database.TimePointerFromNullTime(result.LastUpdatedAt),
		LastAcceptedTermsOfService: database.TimePointerFromNullTime(result.LastAcceptedTermsOfService),
		LastAcceptedPrivacyPolicy:  database.TimePointerFromNullTime(result.LastAcceptedPrivacyPolicy),
		TwoFactorSecretVerifiedAt:  database.TimePointerFromNullTime(result.TwoFactorSecretVerifiedAt),
		AvatarSrc:                  database.StringPointerFromNullString(result.AvatarSrc),
		Birthday:                   database.TimePointerFromNullTime(result.Birthday),
		ArchivedAt:                 database.TimePointerFromNullTime(result.ArchivedAt),
		AccountStatusExplanation:   result.UserAccountStatusExplanation,
		TwoFactorSecret:            result.TwoFactorSecret,
		HashedPassword:             result.HashedPassword,
		ID:                         result.ID,
		AccountStatus:              result.UserAccountStatus,
		Username:                   result.Username,
		FirstName:                  result.FirstName,
		LastName:                   result.LastName,
		EmailAddress:               result.EmailAddress,
		EmailAddressVerifiedAt:     database.TimePointerFromNullTime(result.EmailAddressVerifiedAt),
		ServiceRole:                result.ServiceRole,
		RequiresPasswordChange:     result.RequiresPasswordChange,
	}

	return u, nil
}

func (q *Querier) MarkUserEmailAddressAsVerified(ctx context.Context, userID, token string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if userID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.UserIDKey, userID)

	if token == "" {
		return ErrEmptyInputProvided
	}

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	if err = q.generatedQuerier.MarkEmailAddressAsVerified(ctx, tx, &generated.MarkEmailAddressAsVerifiedParams{
		ID:                            userID,
		EmailAddressVerificationToken: database.NullStringFromString(token),
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		if errors.Is(err, sql.ErrNoRows) {
			return err
		}

		return observability.PrepareAndLogError(err, logger, span, "writing verified email address status to database")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUsers,
		RelevantID:    userID,
		EventType:     types.AuditLogEventTypeUpdated,
		BelongsToUser: userID,
		Changes: map[string]types.ChangeLog{
			"email_address_verification": {
				OldValue: "unverified",
				NewValue: "verified",
			},
		},
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if _, err = q.generatedQuerier.SetUserAccountStatus(ctx, tx, &generated.SetUserAccountStatusParams{
		UserAccountStatus:            string(types.GoodStandingUserAccountStatus),
		UserAccountStatusExplanation: "verified email address",
		ID:                           userID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "updating user account status")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	return nil
}

func (q *Querier) MarkUserEmailAddressAsUnverified(ctx context.Context, userID string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if userID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.UserIDKey, userID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	if err = q.generatedQuerier.MarkEmailAddressAsUnverified(ctx, tx, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			q.rollbackTransaction(ctx, tx)
			return err
		}

		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "writing email address verification status to database")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:            identifiers.New(),
		ResourceType:  resourceTypeUsers,
		RelevantID:    userID,
		EventType:     types.AuditLogEventTypeUpdated,
		BelongsToUser: userID,
		Changes: map[string]types.ChangeLog{
			"email_address_verification": {
				OldValue: "verified",
				NewValue: "unverified",
			},
		},
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if _, err = q.generatedQuerier.SetUserAccountStatus(ctx, tx, &generated.SetUserAccountStatusParams{
		UserAccountStatus:            string(types.UnverifiedAccountStatus),
		UserAccountStatusExplanation: "unverified email address",
		ID:                           userID,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "updating user account status")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	return nil
}
