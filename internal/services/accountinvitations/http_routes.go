package accountinvitations

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/identifiers"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/pointer"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"

	servertiming "github.com/mitchellh/go-server-timing"
)

const (
	// AccountInvitationIDURIParamKey is a standard string that we'll use to refer to account invitation IDs with.
	AccountInvitationIDURIParamKey = "accountInvitationID"
)

var _ types.AccountInvitationDataService = (*service)(nil)

// InviteMemberHandler is our account creation route.
func (s *service) InviteMemberHandler(res http.ResponseWriter, req *http.Request) {
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
	responseDetails.CurrentAccountID = sessionCtxData.ActiveAccountID

	userID := sessionCtxData.Requester.UserID
	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	logger = logger.WithValue(keys.RequesterIDKey, userID)

	accountID := s.accountIDFetcher(req)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)
	logger = logger.WithValue(keys.AccountIDKey, accountID)

	// read parsed input struct from request body.
	providedInput := new(types.AccountInvitationCreationRequestInput)
	if err = s.encoderDecoder.DecodeRequest(ctx, req, providedInput); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	providedInput.ToEmail = strings.TrimSpace(strings.ToLower(providedInput.ToEmail))

	if err = providedInput.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("invalid input attached to request")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	if providedInput.ExpiresAt == nil {
		providedInput.ExpiresAt = pointer.To(time.Now().Add((time.Hour * 24) * 7))
	}

	input := converters.ConvertAccountInvitationCreationInputToAccountInvitationDatabaseCreationInput(providedInput)

	input.ID = identifiers.New()
	input.DestinationAccountID = accountID
	input.FromUser = userID

	token, err := s.secretGenerator.GenerateBase64EncodedString(ctx, 64)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "generating invitation token")
		errRes := types.NewAPIErrorResponse("generating invitation token", types.ErrSecretGeneration, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	input.Token = token

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	user, err := s.userDataManager.GetUserByEmail(ctx, input.ToEmail)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		observability.AcknowledgeError(err, logger, span, "fetching user ID by email")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	if user != nil {
		input.ToUser = &user.ID
	}

	createTimer := timing.NewMetric("database").WithDesc("create").Start()
	accountInvitation, err := s.accountInvitationDataManager.CreateAccountInvitation(ctx, input)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "creating account invitation")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	createTimer.Stop()

	dcm := &types.DataChangeMessage{
		EventType:         types.AccountInvitationCreatedCustomerEventType,
		AccountInvitation: accountInvitation,
		AccountID:         accountID,
		UserID:            userID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[*types.AccountInvitation]{
		Details: responseDetails,
		Data:    accountInvitation,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusCreated)
}

// ReadHandler returns a GET handler that returns a account invitation.
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
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	logger = sessionCtxData.AttachToLogger(logger)
	responseDetails.CurrentAccountID = sessionCtxData.ActiveAccountID // determine relevant account invitation ID.
	accountInvitationID := s.accountInvitationIDFetcher(req)
	tracing.AttachToSpan(span, keys.AccountInvitationIDKey, accountInvitationID)
	logger = logger.WithValue(keys.AccountInvitationIDKey, accountInvitationID)

	tracing.AttachToSpan(span, keys.AccountIDKey, sessionCtxData.ActiveAccountID)
	logger = logger.WithValue(keys.AccountIDKey, sessionCtxData.ActiveAccountID)

	// fetch the account invitation from the database.
	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	accountInvitation, err := s.accountInvitationDataManager.GetAccountInvitationByAccountAndID(ctx, sessionCtxData.ActiveAccountID, accountInvitationID)
	if errors.Is(err, sql.ErrNoRows) {
		logger.Debug("No rows found in account invitation database")
		errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching account invitation from database")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	responseValue := &types.APIResponse[*types.AccountInvitation]{
		Details: responseDetails,
		Data:    accountInvitation,
	}

	// encode the response.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

func (s *service) InboundInvitesHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	filter := types.ExtractQueryFilterFromRequest(req)
	filter.AttachToLogger(logger)

	// determine relevant user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	userID := sessionCtxData.Requester.UserID
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	logger = logger.WithValue(keys.UserIDKey, userID)

	accountID := s.accountIDFetcher(req)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)
	logger = logger.WithValue(keys.AccountIDKey, accountID)

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	invitations, err := s.accountInvitationDataManager.GetPendingAccountInvitationsForUser(ctx, userID, filter)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching outbound invites")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	responseValue := &types.APIResponse[[]*types.AccountInvitation]{
		Details:    responseDetails,
		Data:       invitations.Data,
		Pagination: &invitations.Pagination,
	}

	// encode the response.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

func (s *service) OutboundInvitesHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	filter := types.ExtractQueryFilterFromRequest(req)
	filter.AttachToLogger(logger)

	logger.Debug("fetching outbound invites for account")

	// determine relevant user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	userID := sessionCtxData.Requester.UserID
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	logger = logger.WithValue(keys.UserIDKey, userID)

	accountID := s.accountIDFetcher(req)
	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)
	logger = logger.WithValue(keys.AccountIDKey, accountID)

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	invitations, err := s.accountInvitationDataManager.GetPendingAccountInvitationsFromUser(ctx, userID, filter)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching outbound invites")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	logger.Debug("responding with outbound invites for account")

	responseValue := &types.APIResponse[[]*types.AccountInvitation]{
		Details:    responseDetails,
		Data:       invitations.Data,
		Pagination: &invitations.Pagination,
	}

	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

func (s *service) AcceptInviteHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// determine relevant user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	// read parsed input struct from request body.
	providedInput := new(types.AccountInvitationUpdateRequestInput)
	if err = s.encoderDecoder.DecodeRequest(ctx, req, providedInput); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request")
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

	// note, this is where you would call providedInput.ValidateWithContext, if that currently had any effect.

	userID := sessionCtxData.Requester.UserID
	logger = logger.WithValue(keys.UserIDKey, userID)

	accountInvitationID := s.accountInvitationIDFetcher(req)
	tracing.AttachToSpan(span, keys.AccountInvitationIDKey, accountInvitationID)
	logger = logger.WithValue(keys.AccountInvitationIDKey, accountInvitationID)

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	invitation, err := s.accountInvitationDataManager.GetAccountInvitationByTokenAndID(ctx, providedInput.Token, accountInvitationID)
	if errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving invitation")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	if err = s.accountInvitationDataManager.AcceptAccountInvitation(ctx, invitation.ID, providedInput.Token, providedInput.Note); err != nil {
		observability.AcknowledgeError(err, logger, span, "accepting invitation")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	dcm := &types.DataChangeMessage{
		EventType:           types.AccountInvitationAcceptedCustomerEventType,
		AccountID:           invitation.DestinationAccount.ID,
		AccountInvitationID: accountInvitationID,
		UserID:              sessionCtxData.Requester.UserID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[[]*types.AccountInvitation]{
		Details: responseDetails,
	}

	// encode the response.
	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

func (s *service) CancelInviteHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// determine relevant user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	// read parsed input struct from request body.
	providedInput := new(types.AccountInvitationUpdateRequestInput)
	if err = s.encoderDecoder.DecodeRequest(ctx, req, providedInput); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request")
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

	// note, this is where you would call providedInput.ValidateWithContext, if that currently had any effect.

	userID := sessionCtxData.Requester.UserID
	tracing.AttachToSpan(span, keys.UserIDKey, userID)
	logger = logger.WithValue(keys.UserIDKey, userID)

	accountInvitationID := s.accountInvitationIDFetcher(req)
	tracing.AttachToSpan(span, keys.AccountInvitationIDKey, accountInvitationID)
	logger = logger.WithValue(keys.AccountInvitationIDKey, accountInvitationID)

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	invitation, err := s.accountInvitationDataManager.GetAccountInvitationByTokenAndID(ctx, providedInput.Token, accountInvitationID)
	if errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving invitation")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	if err = s.accountInvitationDataManager.CancelAccountInvitation(ctx, invitation.ID, providedInput.Note); err != nil {
		observability.AcknowledgeError(err, logger, span, "cancelling invitation")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	dcm := &types.DataChangeMessage{
		EventType:           types.AccountInvitationCanceledCustomerEventType,
		AccountID:           invitation.DestinationAccount.ID,
		AccountInvitationID: accountInvitationID,
		UserID:              sessionCtxData.Requester.UserID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[[]*types.AccountInvitation]{
		Details: responseDetails,
	}

	// encode the response.
	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

func (s *service) RejectInviteHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// determine relevant user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	// read parsed input struct from request body.
	providedInput := new(types.AccountInvitationUpdateRequestInput)
	if err = s.encoderDecoder.DecodeRequest(ctx, req, providedInput); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request")
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

	// note, this is where you would call providedInput.ValidateWithContext, if that currently had any effect.

	userID := sessionCtxData.Requester.UserID
	logger = logger.WithValue(keys.UserIDKey, userID)

	accountInvitationID := s.accountInvitationIDFetcher(req)
	tracing.AttachToSpan(span, keys.AccountInvitationIDKey, accountInvitationID)
	logger = logger.WithValue(keys.AccountInvitationIDKey, accountInvitationID)

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	invitation, err := s.accountInvitationDataManager.GetAccountInvitationByTokenAndID(ctx, providedInput.Token, accountInvitationID)
	if errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving invitation")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	if err = s.accountInvitationDataManager.RejectAccountInvitation(ctx, invitation.ID, providedInput.Note); err != nil {
		observability.AcknowledgeError(err, logger, span, "rejecting invitation")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	dcm := &types.DataChangeMessage{
		EventType:           types.AccountInvitationRejectedCustomerEventType,
		AccountID:           invitation.DestinationAccount.ID,
		AccountInvitationID: accountInvitationID,
		UserID:              sessionCtxData.Requester.UserID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[[]*types.AccountInvitation]{
		Details: responseDetails,
	}

	// encode the response.
	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}
