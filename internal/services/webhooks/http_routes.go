package webhooks

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/identifiers"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"

	servertiming "github.com/mitchellh/go-server-timing"
)

const (
	// WebhookIDURIParamKey is a standard string that we'll use to refer to webhook IDs with.
	WebhookIDURIParamKey = "webhookID"
	// WebhookTriggerEventIDURIParamKey is a standard string that we'll use to refer to webhook trigger event IDs with.
	WebhookTriggerEventIDURIParamKey = "webhookTriggerEventID"
)

var (
	_ types.WebhookDataService = (*service)(nil)
)

// CreateWebhookHandler is our webhook creation route.
func (s *service) CreateWebhookHandler(res http.ResponseWriter, req *http.Request) {
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

	providedInput := new(types.WebhookCreationRequestInput)
	if err = s.encoderDecoder.DecodeRequest(ctx, req, providedInput); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	if err = providedInput.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("provided input was invalid")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	input := converters.ConvertWebhookCreationRequestInputToWebhookDatabaseCreationInput(providedInput)
	input.ID = identifiers.New()
	tracing.AttachToSpan(span, keys.WebhookIDKey, input.ID)
	input.BelongsToAccount = sessionCtxData.ActiveAccountID

	createTimer := timing.NewMetric("database").WithDesc("create").Start()
	webhook, err := s.webhookDataManager.CreateWebhook(ctx, input)
	logger.Debug("database call executed")
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "creating webhook in database")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	createTimer.Stop()

	dcm := &types.DataChangeMessage{
		EventType: types.WebhookCreatedCustomerEventType,
		Webhook:   webhook,
		AccountID: sessionCtxData.ActiveAccountID,
		UserID:    sessionCtxData.Requester.UserID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[*types.Webhook]{
		Details: responseDetails,
		Data:    webhook,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusCreated)
}

// ListWebhooksHandler is our list route.
func (s *service) ListWebhooksHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	filter := types.ExtractQueryFilterFromRequest(req)
	logger := filter.AttachToLogger(s.logger)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	tracing.AttachRequestToSpan(span, req)
	tracing.AttachFilterDataToSpan(span, filter.Page, filter.Limit, filter.SortBy)

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

	// find the webhooks.
	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	webhooks, err := s.webhookDataManager.GetWebhooks(ctx, sessionCtxData.ActiveAccountID, filter)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			webhooks = &types.QueryFilteredResult[types.Webhook]{
				Data: []*types.Webhook{},
			}
		} else {
			observability.AcknowledgeError(err, logger, span, "fetching webhooks")
			errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
			return
		}
	}
	readTimer.Stop()

	responseValue := &types.APIResponse[[]*types.Webhook]{
		Details:    responseDetails,
		Pagination: &webhooks.Pagination,
		Data:       webhooks.Data,
	}

	// encode the response.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// ReadWebhookHandler returns a GET handler that returns a webhook.
func (s *service) ReadWebhookHandler(res http.ResponseWriter, req *http.Request) {
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

	// determine relevant webhook ID.
	webhookID := s.webhookIDFetcher(req)
	tracing.AttachToSpan(span, keys.WebhookIDKey, webhookID)
	logger = logger.WithValue(keys.WebhookIDKey, webhookID)

	tracing.AttachToSpan(span, keys.AccountIDKey, sessionCtxData.ActiveAccountID)
	logger = logger.WithValue(keys.AccountIDKey, sessionCtxData.ActiveAccountID)

	// fetch the webhook from the database.
	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	webhook, err := s.webhookDataManager.GetWebhook(ctx, webhookID, sessionCtxData.ActiveAccountID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Debug("No rows found in webhook database")
			errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
			return
		} else {
			observability.AcknowledgeError(err, logger, span, "fetching webhook from database")
			errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
			return
		}
	}
	readTimer.Stop()

	responseValue := &types.APIResponse[*types.Webhook]{
		Details: responseDetails,
		Data:    webhook,
	}

	// encode the response.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// ArchiveWebhookHandler returns a handler that archives a webhook.
func (s *service) ArchiveWebhookHandler(res http.ResponseWriter, req *http.Request) {
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

	userID := sessionCtxData.Requester.UserID
	logger = logger.WithValue(keys.UserIDKey, userID)

	accountID := sessionCtxData.ActiveAccountID
	logger = logger.WithValue(keys.AccountIDKey, accountID)

	// determine relevant webhook ID.
	webhookID := s.webhookIDFetcher(req)
	tracing.AttachToSpan(span, keys.WebhookIDKey, webhookID)
	logger = logger.WithValue(keys.WebhookIDKey, webhookID)

	existenceTimer := timing.NewMetric("database").WithDesc("existence check").Start()
	exists, err := s.webhookDataManager.WebhookExists(ctx, webhookID, accountID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		observability.AcknowledgeError(err, logger, span, "checking webhook existence")
		return
	} else if !exists || errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	}
	existenceTimer.Stop()

	archiveTimer := timing.NewMetric("database").WithDesc("archive").Start()
	if err = s.webhookDataManager.ArchiveWebhook(ctx, webhookID, accountID); err != nil {
		observability.AcknowledgeError(err, logger, span, "archiving webhook in database")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	archiveTimer.Stop()

	dcm := &types.DataChangeMessage{
		EventType: types.WebhookArchivedCustomerEventType,
		AccountID: accountID,
		UserID:    sessionCtxData.Requester.UserID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[*types.Webhook]{
		Details: responseDetails,
	}

	// let everybody go home.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// ArchiveWebhookTriggerEventHandler returns a handler that archives a webhook trigger event.
func (s *service) ArchiveWebhookTriggerEventHandler(res http.ResponseWriter, req *http.Request) {
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

	userID := sessionCtxData.Requester.UserID
	logger = logger.WithValue(keys.UserIDKey, userID)

	accountID := sessionCtxData.ActiveAccountID
	logger = logger.WithValue(keys.AccountIDKey, accountID)

	// determine relevant webhook ID.
	webhookID := s.webhookIDFetcher(req)
	tracing.AttachToSpan(span, keys.WebhookIDKey, webhookID)
	logger = logger.WithValue(keys.WebhookIDKey, webhookID)

	// determine relevant webhook trigger event ID.
	webhookTriggerEventID := s.webhookTriggerEventIDFetcher(req)
	tracing.AttachToSpan(span, keys.WebhookTriggerEventIDKey, webhookTriggerEventID)
	logger = logger.WithValue(keys.WebhookTriggerEventIDKey, webhookTriggerEventID)

	existenceTimer := timing.NewMetric("database").WithDesc("existence check").Start()
	exists, err := s.webhookDataManager.WebhookExists(ctx, webhookID, accountID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		observability.AcknowledgeError(err, logger, span, "checking webhook existence")
		return
	} else if !exists || errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	}
	existenceTimer.Stop()

	archiveTimer := timing.NewMetric("database").WithDesc("archive").Start()
	if err = s.webhookDataManager.ArchiveWebhookTriggerEvent(ctx, webhookID, webhookTriggerEventID); err != nil {
		observability.AcknowledgeError(err, logger, span, "archiving webhook trigger event in database")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	archiveTimer.Stop()

	dcm := &types.DataChangeMessage{
		EventType: types.WebhookArchivedCustomerEventType,
		AccountID: accountID,
		UserID:    sessionCtxData.Requester.UserID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[*types.Webhook]{
		Details: responseDetails,
	}

	// let everybody go home.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}
