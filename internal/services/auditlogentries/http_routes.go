package auditlogentries

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	servertiming "github.com/mitchellh/go-server-timing"
)

const (
	// AuditLogEntryIDURIParamKey is a standard string that we'll use to refer to audit log entry IDs with.
	AuditLogEntryIDURIParamKey = "auditLogEntryID"
)

// ReadAuditLogEntryHandler returns a GET handler that returns a audit log entry.
func (s *service) ReadAuditLogEntryHandler(res http.ResponseWriter, req *http.Request) {
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

	// determine audit log entry ID.
	auditLogEntryID := s.auditLogEntryIDFetcher(req)
	tracing.AttachToSpan(span, keys.AuditLogEntryIDKey, auditLogEntryID)
	logger = logger.WithValue(keys.AuditLogEntryIDKey, auditLogEntryID)

	// fetch audit log entry from database.
	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	x, err := s.auditLogEntryDataManager.GetAuditLogEntry(ctx, auditLogEntryID)
	if errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving audit log entry")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	responseValue := &types.APIResponse[*types.AuditLogEntry]{
		Details: responseDetails,
		Data:    x,
	}

	// encode our response and peace.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// ListUserAuditLogEntriesHandler is our list route.
func (s *service) ListUserAuditLogEntriesHandler(res http.ResponseWriter, req *http.Request) {
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

	resourceTypes := req.URL.Query()[types.AuditLogResourceTypesQueryParamKey]
	tracing.AttachToSpan(span, keys.AuditLogEntryResourceTypesKey, resourceTypes)
	logger = logger.WithValue(keys.AuditLogEntryResourceTypesKey, resourceTypes)

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

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()

	var auditLogEntries *types.QueryFilteredResult[types.AuditLogEntry]
	if len(resourceTypes) == 0 {
		auditLogEntries, err = s.auditLogEntryDataManager.GetAuditLogEntriesForUser(ctx, sessionCtxData.Requester.UserID, filter)
	} else {
		auditLogEntries, err = s.auditLogEntryDataManager.GetAuditLogEntriesForUserAndResourceType(ctx, sessionCtxData.Requester.UserID, resourceTypes, filter)
	}

	if errors.Is(err, sql.ErrNoRows) {
		// in the event no rows exist, return an empty list.
		auditLogEntries = &types.QueryFilteredResult[types.AuditLogEntry]{Data: []*types.AuditLogEntry{}}
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving audit log entries")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	responseValue := &types.APIResponse[[]*types.AuditLogEntry]{
		Details:    responseDetails,
		Data:       auditLogEntries.Data,
		Pagination: &auditLogEntries.Pagination,
	}

	// encode our response and peace.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

func (s *service) ListAccountAuditLogEntriesHandler(res http.ResponseWriter, req *http.Request) {
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

	resourceTypes := req.URL.Query()[types.AuditLogResourceTypesQueryParamKey]
	tracing.AttachToSpan(span, keys.AuditLogEntryResourceTypesKey, resourceTypes)
	logger = logger.WithValue(keys.AuditLogEntryResourceTypesKey, resourceTypes)

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

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	var auditLogEntries *types.QueryFilteredResult[types.AuditLogEntry]
	if len(resourceTypes) == 0 {
		auditLogEntries, err = s.auditLogEntryDataManager.GetAuditLogEntriesForAccount(ctx, sessionCtxData.ActiveAccountID, filter)
	} else {
		auditLogEntries, err = s.auditLogEntryDataManager.GetAuditLogEntriesForAccountAndResourceType(ctx, sessionCtxData.ActiveAccountID, resourceTypes, filter)
	}

	if errors.Is(err, sql.ErrNoRows) {
		// in the event no rows exist, return an empty list.
		auditLogEntries = &types.QueryFilteredResult[types.AuditLogEntry]{Data: []*types.AuditLogEntry{}}
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving audit log entries")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	responseValue := &types.APIResponse[[]*types.AuditLogEntry]{
		Details:    responseDetails,
		Data:       auditLogEntries.Data,
		Pagination: &auditLogEntries.Pagination,
	}

	// encode our response and peace.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}
