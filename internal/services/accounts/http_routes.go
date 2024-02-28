package accounts

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/identifiers"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"

	servertiming "github.com/mitchellh/go-server-timing"
)

const (
	// AccountIDURIParamKey is a standard string that we'll use to refer to account IDs with.
	AccountIDURIParamKey = "accountID"
	// UserIDURIParamKey is a standard string that we'll use to refer to user IDs with.
	UserIDURIParamKey = "userID"
)

var _ types.AccountDataService = (*service)(nil)

// ListHandler is our list route.
func (s *service) ListHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	filter := types.ExtractQueryFilterFromRequest(req)
	logger := s.logger.WithRequest(req).WithSpan(span)
	logger = filter.AttachToLogger(logger)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	tracing.AttachRequestToSpan(span, req)
	tracing.AttachFilterDataToSpan(span, filter.Page, filter.Limit, filter.SortBy)

	// fetch session context data
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()
	requester := sessionCtxData.Requester.UserID
	logger = logger.WithValue(keys.RequesterIDKey, requester)
	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)

	filter.AttachToLogger(logger)

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	accounts, err := s.accountDataManager.GetAccounts(ctx, requester, filter)
	if errors.Is(err, sql.ErrNoRows) {
		// in the event no rows exist, return an empty list.
		accounts = &types.QueryFilteredResult[types.Account]{Data: []*types.Account{}}
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching accounts")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	responseValue := &types.APIResponse[[]*types.Account]{
		Details:    responseDetails,
		Data:       accounts.Data,
		Pagination: &accounts.Pagination,
	}

	// encode our response and say farewell.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// CreateHandler is our account creation route.
func (s *service) CreateHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// retrieve session context data.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	logger = sessionCtxData.AttachToLogger(logger)
	responseDetails.CurrentAccountID = sessionCtxData.ActiveAccountID // read parsed input struct from request body.
	providedInput := new(types.AccountCreationRequestInput)
	if err = s.encoderDecoder.DecodeRequest(ctx, req, providedInput); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	if err = providedInput.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("invalid input attached to request")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	requester := sessionCtxData.Requester.UserID
	logger = logger.WithValue(keys.RequesterIDKey, requester)

	input := converters.ConvertAccountCreationInputToAccountDatabaseCreationInput(providedInput)
	input.ID = identifiers.New()
	input.BelongsToUser = requester

	input.WebhookEncryptionKey, err = s.secretGenerator.GenerateHexEncodedString(ctx, 128)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "generating webhook encryption key")
		errRes := types.NewAPIErrorResponse("encryption key error", types.ErrSecretGeneration, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	logger = logger.WithValue(keys.NameKey, input.Name)

	// create account in database.
	createTimer := timing.NewMetric("database").WithDesc("create").Start()
	account, err := s.accountDataManager.CreateAccount(ctx, input)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "creating account")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	createTimer.Stop()

	logger = logger.WithValue(keys.AccountIDKey, account.ID)
	tracing.AttachToSpan(span, keys.AccountIDKey, account.ID)

	// notify relevant parties.
	logger.Debug("created account")

	dcm := &types.DataChangeMessage{
		EventType: types.AccountCreatedCustomerEventType,
		Account:   account,
		AccountID: account.ID,
		UserID:    sessionCtxData.Requester.UserID,
	}
	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message for created account")
	}

	responseValue := &types.APIResponse[*types.Account]{
		Details: responseDetails,
		Data:    account,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusCreated)
}

// CurrentInfoHandler returns a handler that returns the current account.
func (s *service) CurrentInfoHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	logger.Debug("current account info requested")

	// determine user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		logger.Info("session context data missing from request")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	requester := sessionCtxData.Requester.UserID
	logger = logger.WithValue(keys.RequesterIDKey, requester)
	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)

	// determine account ID.
	accountID := sessionCtxData.ActiveAccountID
	logger = logger.WithValue(keys.AccountIDKey, accountID)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	// fetch account from database.
	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	account, err := s.accountDataManager.GetAccount(ctx, accountID)
	if errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching account from database")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	logger.Debug("responding with current account info")

	responseValue := &types.APIResponse[*types.Account]{
		Details: responseDetails,
		Data:    account,
	}

	// encode our response and peace.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// ReadHandler returns a GET handler that returns a account.
func (s *service) ReadHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// determine user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	requester := sessionCtxData.Requester.UserID
	logger = logger.WithValue(keys.RequesterIDKey, requester)
	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)

	// determine account ID.
	accountID := s.accountIDFetcher(req)
	logger = logger.WithValue(keys.AccountIDKey, accountID)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	// fetch account from database.
	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	account, err := s.accountDataManager.GetAccount(ctx, accountID)
	if errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching account from database")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	admins := []*types.AccountUserMembershipWithUser{}
	plainUsers := []*types.AccountUserMembershipWithUser{}
	for _, member := range account.Members {
		if member.AccountRole == authorization.AccountAdminRole.String() {
			admins = append(admins, member)
		} else {
			plainUsers = append(plainUsers, member)
		}
	}

	account.Members = []*types.AccountUserMembershipWithUser{}
	account.Members = append(account.Members, admins...)
	account.Members = append(account.Members, plainUsers...)

	responseValue := &types.APIResponse[*types.Account]{
		Details: responseDetails,
		Data:    account,
	}

	// encode our response and peace.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// UpdateHandler returns a handler that updates a account.
func (s *service) UpdateHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// determine user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	logger = sessionCtxData.AttachToLogger(logger)
	responseDetails.CurrentAccountID = sessionCtxData.ActiveAccountID

	input := new(types.AccountUpdateRequestInput)
	if err = s.encoderDecoder.DecodeRequest(ctx, req, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	if err = input.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("invalid input attached to request")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	requester := sessionCtxData.Requester.UserID
	logger = logger.WithValue(keys.RequesterIDKey, requester)
	input.BelongsToUser = requester

	// determine account ID.
	accountID := s.accountIDFetcher(req)
	logger = logger.WithValue(keys.AccountIDKey, accountID)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	// fetch account from database.
	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	account, err := s.accountDataManager.GetAccount(ctx, accountID)
	if errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching account from database")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	// update the data structure.
	account.Update(input)

	// update account in database.
	updateTimer := timing.NewMetric("database").WithDesc("update").Start()
	if err = s.accountDataManager.UpdateAccount(ctx, account); err != nil {
		observability.AcknowledgeError(err, logger, span, "updating account")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	updateTimer.Stop()

	dcm := &types.DataChangeMessage{
		EventType: types.AccountUpdatedCustomerEventType,
		Account:   account,
		AccountID: account.ID,
		UserID:    sessionCtxData.Requester.UserID,
	}
	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message for created account")
	}

	responseValue := &types.APIResponse[*types.Account]{
		Details: responseDetails,
		Data:    account,
	}

	// encode our response and peace.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// ArchiveHandler returns a handler that archives a account.
func (s *service) ArchiveHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// determine user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	requester := sessionCtxData.Requester.UserID
	logger = logger.WithValue(keys.RequesterIDKey, requester)
	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)

	// determine account ID.
	accountID := s.accountIDFetcher(req)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)
	logger = logger.WithValue(keys.AccountIDKey, accountID)

	// archive the account in the database.
	archiveTimer := timing.NewMetric("database").WithDesc("archive").Start()
	err = s.accountDataManager.ArchiveAccount(ctx, accountID, requester)
	if errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "archiving account")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	archiveTimer.Stop()

	dcm := &types.DataChangeMessage{
		EventType: types.AccountArchivedCustomerEventType,
		AccountID: accountID,
		UserID:    sessionCtxData.Requester.UserID,
	}
	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message for created account")
	}

	responseValue := &types.APIResponse[*types.Account]{
		Details: responseDetails,
	}

	// let everybody go home.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// ModifyMemberPermissionsHandler is our account creation route.
func (s *service) ModifyMemberPermissionsHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// determine user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	logger = sessionCtxData.AttachToLogger(logger)
	responseDetails.CurrentAccountID = sessionCtxData.ActiveAccountID // read parsed input struct from request body.
	input := new(types.ModifyUserPermissionsInput)
	if err = s.encoderDecoder.DecodeRequest(ctx, req, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	if err = input.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("invalid input attached to request")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	requester := sessionCtxData.Requester.UserID
	logger = logger.WithValue(keys.RequesterIDKey, requester)
	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)

	accountID := s.accountIDFetcher(req)
	logger = logger.WithValue(keys.AccountIDKey, accountID)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	userID := s.userIDFetcher(req)
	logger = logger.WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	// create account in database.
	if err = s.accountMembershipDataManager.ModifyUserPermissions(ctx, accountID, userID, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "modifying user permissions")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	dcm := &types.DataChangeMessage{
		EventType: types.AccountMembershipPermissionsUpdatedCustomerEventType,
		AccountID: accountID,
		UserID:    sessionCtxData.Requester.UserID,
	}
	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message for created account")
	}

	responseValue := &types.APIResponse[*types.Webhook]{
		Details: responseDetails,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// TransferAccountOwnershipHandler is our account creation route.
func (s *service) TransferAccountOwnershipHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// determine user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "transferring account ownership")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	logger = sessionCtxData.AttachToLogger(logger)
	responseDetails.CurrentAccountID = sessionCtxData.ActiveAccountID // read parsed input struct from request body.
	input := new(types.AccountOwnershipTransferInput)
	if err = s.encoderDecoder.DecodeRequest(ctx, req, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	if err = input.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("invalid input attached to request")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	accountID := s.accountIDFetcher(req)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)
	logger = logger.WithValue(keys.AccountIDKey, accountID)

	requester := sessionCtxData.Requester.UserID
	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	logger = logger.WithValue(keys.RequesterIDKey, requester)

	// transfer ownership of account in database.
	if err = s.accountMembershipDataManager.TransferAccountOwnership(ctx, accountID, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "transferring account ownership")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	dcm := &types.DataChangeMessage{
		EventType: types.AccountOwnershipTransferredCustomerEventType,
		AccountID: accountID,
		UserID:    sessionCtxData.Requester.UserID,
	}
	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message for created account")
	}

	responseValue := &types.APIResponse[*types.Webhook]{
		Details: responseDetails,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// RemoveMemberHandler is our account creation route.
func (s *service) RemoveMemberHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// read parsed input struct from request body.
	reason := req.URL.Query().Get("reason")
	logger = logger.WithValue(keys.ReasonKey, reason)

	// determine user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	requester := sessionCtxData.Requester.UserID
	logger = logger.WithValue(keys.RequesterIDKey, requester)
	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)

	accountID := s.accountIDFetcher(req)
	logger = logger.WithValue(keys.AccountIDKey, accountID)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	userID := s.userIDFetcher(req)
	logger = logger.WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	// remove user from account in database.
	if err = s.accountMembershipDataManager.RemoveUserFromAccount(ctx, userID, accountID); err != nil {
		observability.AcknowledgeError(err, logger, span, "removing user from account")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	logger.Info("user removed from account")

	dcm := &types.DataChangeMessage{
		EventType: types.AccountMemberRemovedCustomerEventType,
		AccountID: accountID,
		UserID:    sessionCtxData.Requester.UserID,
	}
	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message for created account")
	}

	responseValue := &types.APIResponse[*types.Webhook]{
		Details: responseDetails,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// MarkAsDefaultAccountHandler is our account creation route.
func (s *service) MarkAsDefaultAccountHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	accountID := s.accountIDFetcher(req)
	logger = logger.WithValue(keys.AccountIDKey, accountID)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	// determine user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	requester := sessionCtxData.Requester.UserID
	logger = logger.WithValue(keys.RequesterIDKey, requester)
	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)

	// mark account as default in database.
	if err = s.accountMembershipDataManager.MarkAccountAsUserDefault(ctx, requester, accountID); err != nil {
		observability.AcknowledgeError(err, logger, span, "marking account as default")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	dcm := &types.DataChangeMessage{
		EventType: types.AccountMemberRemovedCustomerEventType,
		AccountID: accountID,
		UserID:    sessionCtxData.Requester.UserID,
	}
	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message for created account")
	}

	responseValue := &types.APIResponse[*types.Webhook]{
		Details: responseDetails,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}
