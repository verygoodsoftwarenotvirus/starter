package postgres

import (
	"context"
	"strings"

	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres/generated"
	"github.com/verygoodsoftwarenotvirus/starter/internal/identifiers"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	resourceTypeServiceSettings  = "service_settings"
	serviceSettingsEnumDelimiter = "|"
)

var (
	_ types.ServiceSettingDataManager = (*Querier)(nil)
)

// ServiceSettingExists fetches whether a service setting exists from the database.
func (q *Querier) ServiceSettingExists(ctx context.Context, serviceSettingID string) (exists bool, err error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if serviceSettingID == "" {
		return false, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.ServiceSettingIDKey, serviceSettingID)
	tracing.AttachToSpan(span, keys.ServiceSettingIDKey, serviceSettingID)

	result, err := q.generatedQuerier.CheckServiceSettingExistence(ctx, q.db, serviceSettingID)
	if err != nil {
		return false, observability.PrepareAndLogError(err, logger, span, "performing service setting existence check")
	}

	return result, nil
}

// GetServiceSetting fetches a service setting from the database.
func (q *Querier) GetServiceSetting(ctx context.Context, serviceSettingID string) (*types.ServiceSetting, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if serviceSettingID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.ServiceSettingIDKey, serviceSettingID)
	tracing.AttachToSpan(span, keys.ServiceSettingIDKey, serviceSettingID)

	result, err := q.generatedQuerier.GetServiceSetting(ctx, q.db, serviceSettingID)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "performing service setting fetch")
	}

	usableEnumeration := []string{}
	for _, x := range strings.Split(result.Enumeration, serviceSettingsEnumDelimiter) {
		if strings.TrimSpace(x) != "" {
			usableEnumeration = append(usableEnumeration, x)
		}
	}

	serviceSetting := &types.ServiceSetting{
		CreatedAt:     result.CreatedAt,
		DefaultValue:  database.StringPointerFromNullString(result.DefaultValue),
		LastUpdatedAt: database.TimePointerFromNullTime(result.LastUpdatedAt),
		ArchivedAt:    database.TimePointerFromNullTime(result.ArchivedAt),
		ID:            result.ID,
		Name:          result.Name,
		Type:          string(result.Type),
		Description:   result.Description,
		Enumeration:   usableEnumeration,
		AdminsOnly:    result.AdminsOnly,
	}

	return serviceSetting, nil
}

// SearchForServiceSettings fetches a service setting from the database.
func (q *Querier) SearchForServiceSettings(ctx context.Context, query string) ([]*types.ServiceSetting, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if query == "" {
		return nil, ErrEmptyInputProvided
	}
	logger = logger.WithValue(keys.SearchQueryKey, query)
	tracing.AttachToSpan(span, keys.ServiceSettingIDKey, query)

	results, err := q.generatedQuerier.SearchForServiceSettings(ctx, q.db, query)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "executing service settings list retrieval query")
	}

	x := []*types.ServiceSetting{}
	for _, result := range results {
		rawEnumeration := strings.Split(result.Enumeration, serviceSettingsEnumDelimiter)
		usableEnumeration := []string{}
		for _, y := range rawEnumeration {
			if strings.TrimSpace(y) != "" {
				usableEnumeration = append(usableEnumeration, y)
			}
		}

		serviceSetting := &types.ServiceSetting{
			CreatedAt:     result.CreatedAt,
			DefaultValue:  database.StringPointerFromNullString(result.DefaultValue),
			LastUpdatedAt: database.TimePointerFromNullTime(result.LastUpdatedAt),
			ArchivedAt:    database.TimePointerFromNullTime(result.ArchivedAt),
			ID:            result.ID,
			Name:          result.Name,
			Type:          string(result.Type),
			Description:   result.Description,
			Enumeration:   usableEnumeration,
			AdminsOnly:    result.AdminsOnly,
		}

		x = append(x, serviceSetting)
	}

	return x, nil
}

// GetServiceSettings fetches a list of service settings from the database that meet a particular filter.
func (q *Querier) GetServiceSettings(ctx context.Context, filter *types.QueryFilter) (x *types.QueryFilteredResult[types.ServiceSetting], err error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if filter == nil {
		filter = types.DefaultQueryFilter()
	}
	logger = filter.AttachToLogger(logger)
	tracing.AttachQueryFilterToSpan(span, filter)

	x = &types.QueryFilteredResult[types.ServiceSetting]{
		Pagination: filter.ToPagination(),
	}

	results, err := q.generatedQuerier.GetServiceSettings(ctx, q.db, &generated.GetServiceSettingsParams{
		CreatedBefore: database.NullTimeFromTimePointer(filter.CreatedBefore),
		CreatedAfter:  database.NullTimeFromTimePointer(filter.CreatedAfter),
		UpdatedBefore: database.NullTimeFromTimePointer(filter.UpdatedBefore),
		UpdatedAfter:  database.NullTimeFromTimePointer(filter.UpdatedAfter),
		QueryOffset:   database.NullInt32FromUint16(filter.QueryOffset()),
		QueryLimit:    database.NullInt32FromUint8Pointer(filter.Limit),
	})
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "executing service settings list retrieval query")
	}

	for _, result := range results {
		rawEnumeration := strings.Split(result.Enumeration, serviceSettingsEnumDelimiter)
		usableEnumeration := []string{}
		for _, y := range rawEnumeration {
			if strings.TrimSpace(y) != "" {
				usableEnumeration = append(usableEnumeration, y)
			}
		}

		x.Data = append(x.Data, &types.ServiceSetting{
			CreatedAt:     result.CreatedAt,
			DefaultValue:  database.StringPointerFromNullString(result.DefaultValue),
			LastUpdatedAt: database.TimePointerFromNullTime(result.LastUpdatedAt),
			ArchivedAt:    database.TimePointerFromNullTime(result.ArchivedAt),
			ID:            result.ID,
			Name:          result.Name,
			Type:          string(result.Type),
			Description:   result.Description,
			Enumeration:   usableEnumeration,
			AdminsOnly:    result.AdminsOnly,
		})
		x.FilteredCount = uint64(result.FilteredCount)
		x.TotalCount = uint64(result.TotalCount)
	}

	return x, nil
}

// CreateServiceSetting creates a service setting in the database.
func (q *Querier) CreateServiceSetting(ctx context.Context, input *types.ServiceSettingDatabaseCreationInput) (*types.ServiceSetting, error) {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}
	tracing.AttachToSpan(span, keys.ServiceSettingIDKey, input.ID)
	logger := q.logger.WithValue(keys.ServiceSettingIDKey, input.ID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	// create the service setting.
	if err = q.generatedQuerier.CreateServiceSetting(ctx, tx, &generated.CreateServiceSettingParams{
		ID:           input.ID,
		Name:         input.Name,
		Type:         generated.SettingType(input.Type),
		Description:  input.Description,
		Enumeration:  strings.Join(input.Enumeration, serviceSettingsEnumDelimiter),
		DefaultValue: database.NullStringFromStringPointer(input.DefaultValue),
		AdminsOnly:   input.AdminsOnly,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return nil, observability.PrepareAndLogError(err, logger, span, "performing service setting creation query")
	}

	x := &types.ServiceSetting{
		ID:           input.ID,
		Name:         input.Name,
		Type:         input.Type,
		Description:  input.Description,
		DefaultValue: input.DefaultValue,
		AdminsOnly:   input.AdminsOnly,
		Enumeration:  input.Enumeration,
		CreatedAt:    q.currentTime(),
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:           identifiers.New(),
		ResourceType: resourceTypeServiceSettings,
		RelevantID:   x.ID,
		EventType:    types.AuditLogEventTypeCreated,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return nil, observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("service setting created")

	return x, nil
}

// ArchiveServiceSetting archives a service setting from the database by its ID.
func (q *Querier) ArchiveServiceSetting(ctx context.Context, serviceSettingID string) error {
	ctx, span := q.tracer.StartSpan(ctx)
	defer span.End()

	logger := q.logger.Clone()

	if serviceSettingID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.ServiceSettingIDKey, serviceSettingID)
	tracing.AttachToSpan(span, keys.ServiceSettingIDKey, serviceSettingID)

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "beginning transaction")
	}

	if _, err = q.generatedQuerier.ArchiveServiceSetting(ctx, q.db, serviceSettingID); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareAndLogError(err, logger, span, "updating service setting")
	}

	if _, err = q.createAuditLogEntry(ctx, tx, &types.AuditLogEntryDatabaseCreationInput{
		ID:           identifiers.New(),
		ResourceType: resourceTypeServiceSettings,
		RelevantID:   serviceSettingID,
		EventType:    types.AuditLogEventTypeArchived,
	}); err != nil {
		q.rollbackTransaction(ctx, tx)
		return observability.PrepareError(err, span, "creating audit log entry")
	}

	if err = tx.Commit(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "committing transaction")
	}

	logger.Info("service setting archived")

	return nil
}
