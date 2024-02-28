package postgres

import (
	"context"
	"database/sql"
	"errors"
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

var (
	_ types.AccountInvitationDataManager = (*Querier)(nil)
)

// AccountInvitationExists fetches whether a account invitation exists from the database.
func (q *Querier) AccountInvitationExists(ctx context.Context, accountInvitationID string) (bool, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if accountInvitationID == "" {
		return false, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AccountInvitationIDKey, accountInvitationID)
	tracing.AttachToSpan(span, keys.AccountInvitationIDKey, accountInvitationID)

	result, err := q.generatedQuerier.CheckAccountInvitationExistence(ctx, q.db, accountInvitationID)
	if err != nil {
		return false, observability.PrepareAndLogError(err, logger, span, "performing account invitation existence check")
	}

	return result, nil
}

// GetAccountInvitationByAccountAndID fetches an invitation from the database.
func (q *Querier) GetAccountInvitationByAccountAndID(ctx context.Context, accountID, accountInvitationID string) (*types.AccountInvitation, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if accountID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AccountIDKey, accountID)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	if accountInvitationID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AccountInvitationIDKey, accountInvitationID)
	tracing.AttachToSpan(span, keys.AccountInvitationIDKey, accountInvitationID)

	result, err := q.generatedQuerier.GetAccountInvitationByAccountAndID(ctx, q.db, &generated.GetAccountInvitationByAccountAndIDParams{
		DestinationAccount: accountID,
		ID:                 accountInvitationID,
	})
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "fetching account invitation")
	}

	accountInvitation := &types.AccountInvitation{
		CreatedAt:     result.CreatedAt,
		LastUpdatedAt: database.TimePointerFromNullTime(result.LastUpdatedAt),
		ArchivedAt:    database.TimePointerFromNullTime(result.ArchivedAt),
		ToUser:        database.StringPointerFromNullString(result.ToUser),
		Status:        string(result.Status),
		ToEmail:       result.ToEmail,
		StatusNote:    result.StatusNote,
		Token:         result.Token,
		ID:            result.ID,
		Note:          result.Note,
		ToName:        result.ToName,
		ExpiresAt:     result.ExpiresAt,
		DestinationAccount: types.Account{
			CreatedAt:                  result.AccountCreatedAt,
			SubscriptionPlanID:         database.StringPointerFromNullString(result.AccountSubscriptionPlanID),
			LastUpdatedAt:              database.TimePointerFromNullTime(result.AccountLastUpdatedAt),
			ArchivedAt:                 database.TimePointerFromNullTime(result.AccountArchivedAt),
			ContactPhone:               result.AccountContactPhone,
			BillingStatus:              result.AccountBillingStatus,
			AddressLine1:               result.AccountAddressLine1,
			AddressLine2:               result.AccountAddressLine2,
			City:                       result.AccountCity,
			State:                      result.AccountState,
			ZipCode:                    result.AccountZipCode,
			Country:                    result.AccountCountry,
			Latitude:                   database.Float64PointerFromNullString(result.AccountLatitude),
			Longitude:                  database.Float64PointerFromNullString(result.AccountLongitude),
			PaymentProcessorCustomerID: result.AccountPaymentProcessorCustomerID,
			BelongsToUser:              result.AccountBelongsToUser,
			ID:                         result.AccountID,
			Name:                       result.AccountName,
			Members:                    nil,
		},
		FromUser: types.User{
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
			TwoFactorSecret:            result.UserTwoFactorSecret,
			HashedPassword:             result.UserHashedPassword,
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
	}

	return accountInvitation, nil
}

// GetAccountInvitationByTokenAndID fetches an invitation from the database.
func (q *Querier) GetAccountInvitationByTokenAndID(ctx context.Context, token, invitationID string) (*types.AccountInvitation, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if token == "" {
		return nil, ErrInvalidIDProvided
	}

	if invitationID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AccountInvitationIDKey, invitationID)
	tracing.AttachToSpan(span, keys.AccountInvitationIDKey, invitationID)

	logger.Debug("fetching account invitation")

	result, err := q.generatedQuerier.GetAccountInvitationByTokenAndID(ctx, q.db, &generated.GetAccountInvitationByTokenAndIDParams{
		Token: token,
		ID:    invitationID,
	})
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "fetching account invitation")
	}

	accountInvitation := &types.AccountInvitation{
		CreatedAt:     result.CreatedAt,
		LastUpdatedAt: database.TimePointerFromNullTime(result.LastUpdatedAt),
		ArchivedAt:    database.TimePointerFromNullTime(result.ArchivedAt),
		ToUser:        database.StringPointerFromNullString(result.ToUser),
		Status:        string(result.Status),
		ToEmail:       result.ToEmail,
		StatusNote:    result.StatusNote,
		Token:         result.Token,
		ID:            result.ID,
		Note:          result.Note,
		ToName:        result.ToName,
		ExpiresAt:     result.ExpiresAt,
		DestinationAccount: types.Account{
			CreatedAt:                  result.AccountCreatedAt,
			SubscriptionPlanID:         database.StringPointerFromNullString(result.AccountSubscriptionPlanID),
			LastUpdatedAt:              database.TimePointerFromNullTime(result.AccountLastUpdatedAt),
			ArchivedAt:                 database.TimePointerFromNullTime(result.AccountArchivedAt),
			ContactPhone:               result.AccountContactPhone,
			BillingStatus:              result.AccountBillingStatus,
			AddressLine1:               result.AccountAddressLine1,
			AddressLine2:               result.AccountAddressLine2,
			City:                       result.AccountCity,
			State:                      result.AccountState,
			ZipCode:                    result.AccountZipCode,
			Country:                    result.AccountCountry,
			Latitude:                   database.Float64PointerFromNullString(result.AccountLatitude),
			Longitude:                  database.Float64PointerFromNullString(result.AccountLongitude),
			PaymentProcessorCustomerID: result.AccountPaymentProcessorCustomerID,
			BelongsToUser:              result.AccountBelongsToUser,
			ID:                         result.AccountID,
			Name:                       result.AccountName,
			Members:                    nil,
		},
		FromUser: types.User{
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
			TwoFactorSecret:            result.UserTwoFactorSecret,
			HashedPassword:             result.UserHashedPassword,
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
	}

	return accountInvitation, nil
}

// GetAccountInvitationByEmailAndToken fetches an invitation from the database.
func (q *Querier) GetAccountInvitationByEmailAndToken(ctx context.Context, emailAddress, token string) (*types.AccountInvitation, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if emailAddress == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.UserEmailAddressKey, emailAddress)
	tracing.AttachToSpan(span, keys.UserEmailAddressKey, emailAddress)

	if token == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AccountInvitationTokenKey, token)
	tracing.AttachToSpan(span, keys.AccountInvitationTokenKey, token)

	result, err := q.generatedQuerier.GetAccountInvitationByEmailAndToken(ctx, q.db, &generated.GetAccountInvitationByEmailAndTokenParams{
		ToEmail: emailAddress,
		Token:   token,
	})
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "fetching account invitation")
	}

	invitation := &types.AccountInvitation{
		CreatedAt:     result.CreatedAt,
		LastUpdatedAt: database.TimePointerFromNullTime(result.LastUpdatedAt),
		ArchivedAt:    database.TimePointerFromNullTime(result.ArchivedAt),
		ToUser:        database.StringPointerFromNullString(result.ToUser),
		Status:        string(result.Status),
		ToEmail:       result.ToEmail,
		StatusNote:    result.StatusNote,
		Token:         result.Token,
		ID:            result.ID,
		Note:          result.Note,
		ToName:        result.ToName,
		ExpiresAt:     result.ExpiresAt,
		DestinationAccount: types.Account{
			CreatedAt:                  result.AccountCreatedAt,
			SubscriptionPlanID:         database.StringPointerFromNullString(result.AccountSubscriptionPlanID),
			LastUpdatedAt:              database.TimePointerFromNullTime(result.AccountLastUpdatedAt),
			ArchivedAt:                 database.TimePointerFromNullTime(result.AccountArchivedAt),
			ContactPhone:               result.AccountContactPhone,
			BillingStatus:              result.AccountBillingStatus,
			AddressLine1:               result.AccountAddressLine1,
			AddressLine2:               result.AccountAddressLine2,
			City:                       result.AccountCity,
			State:                      result.AccountState,
			ZipCode:                    result.AccountZipCode,
			Country:                    result.AccountCountry,
			Latitude:                   database.Float64PointerFromNullString(result.AccountLatitude),
			Longitude:                  database.Float64PointerFromNullString(result.AccountLongitude),
			PaymentProcessorCustomerID: result.AccountPaymentProcessorCustomerID,
			BelongsToUser:              result.AccountBelongsToUser,
			ID:                         result.AccountID,
			Name:                       result.AccountName,
			Members:                    nil,
		},
		FromUser: types.User{
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
			TwoFactorSecret:            result.UserTwoFactorSecret,
			HashedPassword:             result.UserHashedPassword,
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
	}

	return invitation, nil
}

// CreateAccountInvitation creates an invitation in a database.
func (q *Querier) CreateAccountInvitation(ctx context.Context, input *types.AccountInvitationDatabaseCreationInput) (*types.AccountInvitation, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	logger := q.logger.WithValue(keys.AccountInvitationIDKey, input.ID)
	tracing.AttachToSpan(span, keys.AccountIDKey, input.DestinationAccountID)

	if err := q.generatedQuerier.CreateAccountInvitation(ctx, q.db, &generated.CreateAccountInvitationParams{
		ExpiresAt:          input.ExpiresAt,
		ID:                 input.ID,
		FromUser:           input.FromUser,
		ToName:             input.ToName,
		Note:               input.Note,
		ToEmail:            input.ToEmail,
		Token:              input.Token,
		DestinationAccount: input.DestinationAccountID,
		ToUser:             database.NullStringFromStringPointer(input.ToUser),
	}); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "performing account invitation creation query")
	}

	x := &types.AccountInvitation{
		ID:                 input.ID,
		FromUser:           types.User{ID: input.FromUser},
		ToUser:             input.ToUser,
		Note:               input.Note,
		ToName:             input.ToName,
		ToEmail:            input.ToEmail,
		Token:              input.Token,
		StatusNote:         "",
		Status:             string(types.PendingAccountInvitationStatus),
		DestinationAccount: types.Account{ID: input.DestinationAccountID},
		ExpiresAt:          input.ExpiresAt,
		CreatedAt:          q.currentTime(),
	}

	tracing.AttachToSpan(span, keys.AccountInvitationIDKey, x.ID)
	logger = logger.WithValue(keys.AccountInvitationIDKey, x.ID)

	logger.Info("account invitation created")

	return x, nil
}

// GetPendingAccountInvitationsFromUser fetches pending account invitations sent from a given user.
func (q *Querier) GetPendingAccountInvitationsFromUser(ctx context.Context, userID string, filter *types.QueryFilter) (*types.QueryFilteredResult[types.AccountInvitation], error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if filter == nil {
		filter = types.DefaultQueryFilter()
	}
	logger := q.logger.WithValue(keys.UserIDKey, userID)
	filter.AttachToLogger(logger)

	x := &types.QueryFilteredResult[types.AccountInvitation]{
		Pagination: filter.ToPagination(),
	}

	results, err := q.generatedQuerier.GetPendingInvitesFromUser(ctx, q.db, &generated.GetPendingInvitesFromUserParams{
		CreatedBefore: database.NullTimeFromTimePointer(filter.CreatedBefore),
		CreatedAfter:  database.NullTimeFromTimePointer(filter.CreatedAfter),
		UpdatedBefore: database.NullTimeFromTimePointer(filter.UpdatedBefore),
		UpdatedAfter:  database.NullTimeFromTimePointer(filter.UpdatedAfter),
		QueryOffset:   database.NullInt32FromUint16(filter.QueryOffset()),
		QueryLimit:    database.NullInt32FromUint8Pointer(filter.Limit),
		Status:        generated.InvitationState(types.PendingAccountInvitationStatus),
		FromUser:      userID,
	})
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "performing account invitation query")
	}

	for _, result := range results {
		x.Data = append(x.Data, &types.AccountInvitation{
			CreatedAt:     result.CreatedAt,
			LastUpdatedAt: database.TimePointerFromNullTime(result.LastUpdatedAt),
			ArchivedAt:    database.TimePointerFromNullTime(result.ArchivedAt),
			ToUser:        database.StringPointerFromNullString(result.ToUser),
			Status:        string(result.Status),
			ToEmail:       result.ToEmail,
			StatusNote:    result.StatusNote,
			Token:         result.Token,
			ID:            result.ID,
			Note:          result.Note,
			ToName:        result.ToName,
			ExpiresAt:     result.ExpiresAt,
			DestinationAccount: types.Account{
				CreatedAt:                  result.AccountCreatedAt,
				SubscriptionPlanID:         database.StringPointerFromNullString(result.AccountSubscriptionPlanID),
				LastUpdatedAt:              database.TimePointerFromNullTime(result.AccountLastUpdatedAt),
				ArchivedAt:                 database.TimePointerFromNullTime(result.AccountArchivedAt),
				ContactPhone:               result.AccountContactPhone,
				BillingStatus:              result.AccountBillingStatus,
				AddressLine1:               result.AccountAddressLine1,
				AddressLine2:               result.AccountAddressLine2,
				City:                       result.AccountCity,
				State:                      result.AccountState,
				ZipCode:                    result.AccountZipCode,
				Country:                    result.AccountCountry,
				Latitude:                   database.Float64PointerFromNullString(result.AccountLatitude),
				Longitude:                  database.Float64PointerFromNullString(result.AccountLongitude),
				PaymentProcessorCustomerID: result.AccountPaymentProcessorCustomerID,
				BelongsToUser:              result.AccountBelongsToUser,
				ID:                         result.AccountID,
				Name:                       result.AccountName,
				Members:                    nil,
			},
			FromUser: types.User{
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
				TwoFactorSecret:            result.UserTwoFactorSecret,
				HashedPassword:             result.UserHashedPassword,
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
		})

		x.FilteredCount = uint64(result.FilteredCount)
		x.TotalCount = uint64(result.TotalCount)
	}

	return x, nil
}

// GetPendingAccountInvitationsForUser fetches pending account invitations sent to a given user.
func (q *Querier) GetPendingAccountInvitationsForUser(ctx context.Context, userID string, filter *types.QueryFilter) (*types.QueryFilteredResult[types.AccountInvitation], error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if filter == nil {
		filter = types.DefaultQueryFilter()
	}
	logger := q.logger.WithValue(keys.UserIDKey, userID)
	filter.AttachToLogger(logger)

	x := &types.QueryFilteredResult[types.AccountInvitation]{
		Pagination: filter.ToPagination(),
	}

	results, err := q.generatedQuerier.GetPendingInvitesForUser(ctx, q.db, &generated.GetPendingInvitesForUserParams{
		CreatedBefore: database.NullTimeFromTimePointer(filter.CreatedBefore),
		CreatedAfter:  database.NullTimeFromTimePointer(filter.CreatedAfter),
		UpdatedBefore: database.NullTimeFromTimePointer(filter.UpdatedBefore),
		UpdatedAfter:  database.NullTimeFromTimePointer(filter.UpdatedAfter),
		QueryOffset:   database.NullInt32FromUint16(filter.QueryOffset()),
		QueryLimit:    database.NullInt32FromUint8Pointer(filter.Limit),
		Status:        generated.InvitationState(types.PendingAccountInvitationStatus),
		ToUser:        database.NullStringFromString(userID),
	})
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "performing account invitation query")
	}

	for _, result := range results {
		x.Data = append(x.Data, &types.AccountInvitation{
			CreatedAt:     result.CreatedAt,
			LastUpdatedAt: database.TimePointerFromNullTime(result.LastUpdatedAt),
			ArchivedAt:    database.TimePointerFromNullTime(result.ArchivedAt),
			ToUser:        database.StringPointerFromNullString(result.ToUser),
			Status:        string(result.Status),
			ToEmail:       result.ToEmail,
			StatusNote:    result.StatusNote,
			Token:         result.Token,
			ID:            result.ID,
			Note:          result.Note,
			ToName:        result.ToName,
			ExpiresAt:     result.ExpiresAt,
			DestinationAccount: types.Account{
				CreatedAt:                  result.AccountCreatedAt,
				SubscriptionPlanID:         database.StringPointerFromNullString(result.AccountSubscriptionPlanID),
				LastUpdatedAt:              database.TimePointerFromNullTime(result.AccountLastUpdatedAt),
				ArchivedAt:                 database.TimePointerFromNullTime(result.AccountArchivedAt),
				ContactPhone:               result.AccountContactPhone,
				BillingStatus:              result.AccountBillingStatus,
				AddressLine1:               result.AccountAddressLine1,
				AddressLine2:               result.AccountAddressLine2,
				City:                       result.AccountCity,
				State:                      result.AccountState,
				ZipCode:                    result.AccountZipCode,
				Country:                    result.AccountCountry,
				Latitude:                   database.Float64PointerFromNullString(result.AccountLatitude),
				Longitude:                  database.Float64PointerFromNullString(result.AccountLongitude),
				PaymentProcessorCustomerID: result.AccountPaymentProcessorCustomerID,
				BelongsToUser:              result.AccountBelongsToUser,
				ID:                         result.AccountID,
				Name:                       result.AccountName,
				Members:                    nil,
			},
			FromUser: types.User{
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
				TwoFactorSecret:            result.UserTwoFactorSecret,
				HashedPassword:             result.UserHashedPassword,
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
		})

		x.FilteredCount = uint64(result.FilteredCount)
		x.TotalCount = uint64(result.TotalCount)
	}

	return x, nil
}

func (q *Querier) setInvitationStatus(ctx context.Context, querier database.SQLQueryExecutor, accountInvitationID, note, status string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.WithValue("new_status", status)

	if accountInvitationID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AccountInvitationIDKey, accountInvitationID)
	tracing.AttachToSpan(span, keys.AccountInvitationIDKey, accountInvitationID)

	if err := q.generatedQuerier.SetAccountInvitationStatus(ctx, querier, &generated.SetAccountInvitationStatusParams{
		Status:     generated.InvitationState(status),
		StatusNote: note,
		ID:         accountInvitationID,
	}); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "changing account invitation status")
	}

	logger.Debug("account invitation updated")

	return nil
}

// CancelAccountInvitation cancels a account invitation by its ID with a note.
func (q *Querier) CancelAccountInvitation(ctx context.Context, accountInvitationID, note string) error {
	return q.setInvitationStatus(ctx, q.db, accountInvitationID, note, string(types.CancelledAccountInvitationStatus))
}

// AcceptAccountInvitation accepts a account invitation by its ID with a note.
func (q *Querier) AcceptAccountInvitation(ctx context.Context, accountInvitationID, token, note string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if accountInvitationID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AccountInvitationIDKey, accountInvitationID)
	tracing.AttachToSpan(span, keys.AccountInvitationIDKey, accountInvitationID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	if err = q.setInvitationStatus(ctx, tx, accountInvitationID, note, string(types.AcceptedAccountInvitationStatus)); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "accepting account invitation")
	}

	invitation, err := q.GetAccountInvitationByTokenAndID(ctx, token, accountInvitationID)
	if err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "fetching account invitation")
	}

	addUserInput := &types.AccountUserMembershipDatabaseCreationInput{
		ID:          identifiers.New(),
		Reason:      fmt.Sprintf("accepted account invitation %q", accountInvitationID),
		AccountID:   invitation.DestinationAccount.ID,
		AccountRole: "account_member",
	}
	if invitation.ToUser != nil {
		addUserInput.UserID = *invitation.ToUser
	}

	if err = q.addUserToAccount(ctx, tx, addUserInput); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "adding user to account")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	return nil
}

// RejectAccountInvitation rejects a account invitation by its ID with a note.
func (q *Querier) RejectAccountInvitation(ctx context.Context, accountInvitationID, note string) error {
	return q.setInvitationStatus(ctx, q.db, accountInvitationID, note, string(types.RejectedAccountInvitationStatus))
}

func (q *Querier) attachInvitationsToUser(ctx context.Context, querier database.SQLQueryExecutor, userEmail, userID string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger

	if userEmail == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.UserEmailAddressKey, userEmail)
	tracing.AttachToSpan(span, keys.AccountIDKey, userEmail)

	if userID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.AccountInvitationIDKey, userID)

	if err := q.generatedQuerier.AttachAccountInvitationsToUserID(ctx, querier, &generated.AttachAccountInvitationsToUserIDParams{
		ToEmail: userEmail,
		ToUser:  database.NullStringFromString(userID),
	}); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return observability.PrepareAndLogError(err, logger, span, "attaching invitations to user")
	}

	logger.Info("invitations associated with user")

	return nil
}

func (q *Querier) acceptInvitationForUser(ctx context.Context, querier database.SQLQueryExecutorAndTransactionManager, input *types.UserDatabaseCreationInput) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.WithValue(keys.UsernameKey, input.Username).WithValue(keys.UserEmailAddressKey, input.EmailAddress)

	invitation, tokenCheckErr := q.GetAccountInvitationByEmailAndToken(ctx, input.EmailAddress, input.InvitationToken)
	if tokenCheckErr != nil {
		q.rollbackTransaction(ctx, querier)
		return observability.PrepareError(tokenCheckErr, span, "fetching account invitation")
	}

	logger.Debug("fetched invitation to accept for user")

	if err := q.generatedQuerier.CreateAccountUserMembershipForNewUser(ctx, querier, &generated.CreateAccountUserMembershipForNewUserParams{
		ID:               identifiers.New(),
		BelongsToUser:    input.ID,
		BelongsToAccount: input.DestinationAccountID,
		AccountRole:      authorization.AccountMemberRole.String(),
		DefaultAccount:   true,
	}); err != nil {
		q.rollbackTransaction(ctx, querier)
		return observability.PrepareAndLogError(err, logger, span, "writing destination account membership")
	}

	logger.Debug("created membership via invitation")

	if err := q.setInvitationStatus(ctx, querier, invitation.ID, "", string(types.AcceptedAccountInvitationStatus)); err != nil {
		q.rollbackTransaction(ctx, querier)
		return observability.PrepareAndLogError(err, logger, span, "accepting account invitation")
	}

	logger.Debug("marked invitation as accepted")

	return nil
}
