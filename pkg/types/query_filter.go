package types

import (
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/pointer"
)

const (
	// MaxLimit is the maximum value for list queries.
	MaxLimit = 250
	// DefaultLimit represents how many results we return in a response by default.
	DefaultLimit = 50

	// SearchQueryKey is the query param key to find search queries in requests.
	SearchQueryKey = "q"
	// SearchWithDatabaseQueryKey is the query param key to find search queries in requests.
	SearchWithDatabaseQueryKey = "useDB"
	// LimitQueryKey is the query param key to specify a limit in a query.
	LimitQueryKey = "limit"

	pageQueryKey            = "page"
	createdBeforeQueryKey   = "createdBefore"
	createdAfterQueryKey    = "createdAfter"
	updatedBeforeQueryKey   = "updatedBefore"
	updatedAfterQueryKey    = "updatedAfter"
	includeArchivedQueryKey = "includeArchived"
	sortByQueryKey          = "sortBy"
)

// QueryFilter represents all the filters a User could apply to a list query.
type QueryFilter struct {
	_ struct{} `json:"-"`

	SortBy          *string    `json:"sortBy"`
	Page            *uint16    `json:"page"`
	CreatedAfter    *time.Time `json:"createdBefore,omitempty"`
	CreatedBefore   *time.Time `json:"createdAfter,omitempty"`
	UpdatedAfter    *time.Time `json:"updatedBefore,omitempty"`
	UpdatedBefore   *time.Time `json:"updatedAfter,omitempty"`
	Limit           *uint8     `json:"limit"`
	IncludeArchived *bool      `json:"includeArchived,omitempty"`
}

// DefaultQueryFilter builds the default query filter.
func DefaultQueryFilter() *QueryFilter {
	return &QueryFilter{
		Page:   pointer.To(uint16(1)),
		Limit:  pointer.To(uint8(DefaultLimit)),
		SortBy: SortAscending,
	}
}

// AttachToLogger attaches a QueryFilter's values to a logging.Logger.
func (qf *QueryFilter) AttachToLogger(logger logging.Logger) logging.Logger {
	l := logging.EnsureLogger(logger).Clone()

	if qf == nil {
		return l.WithValue(keys.FilterIsNilKey, true)
	}

	if qf.Page != nil {
		l = l.WithValue(pageQueryKey, qf.Page)
	}

	if qf.Limit != nil {
		l = l.WithValue(LimitQueryKey, qf.Limit)
	}

	if qf.SortBy != nil {
		l = l.WithValue(sortByQueryKey, qf.SortBy)
	}

	if qf.CreatedBefore != nil {
		l = l.WithValue(createdBeforeQueryKey, qf.CreatedBefore)
	}

	if qf.CreatedAfter != nil {
		l = l.WithValue(createdAfterQueryKey, qf.CreatedAfter)
	}

	if qf.UpdatedBefore != nil {
		l = l.WithValue(updatedBeforeQueryKey, qf.UpdatedBefore)
	}

	if qf.UpdatedAfter != nil {
		l = l.WithValue(updatedAfterQueryKey, qf.UpdatedAfter)
	}

	return l
}

// FromParams overrides the core QueryFilter values with values retrieved from url.Params.
func (qf *QueryFilter) FromParams(params url.Values) {
	if i, err := strconv.ParseUint(params.Get(pageQueryKey), 10, 64); err == nil {
		qf.Page = pointer.To(uint16(math.Max(float64(i), 1)))
	}

	if i, err := strconv.ParseUint(params.Get(LimitQueryKey), 10, 64); err == nil {
		qf.Limit = pointer.To(uint8(math.Min(math.Max(float64(i), 0), MaxLimit)))
	}

	if t, err := time.Parse(time.RFC3339Nano, params.Get(createdBeforeQueryKey)); err == nil {
		qf.CreatedBefore = &t
	}

	if t, err := time.Parse(time.RFC3339Nano, params.Get(createdAfterQueryKey)); err == nil {
		qf.CreatedAfter = &t
	}

	if t, err := time.Parse(time.RFC3339Nano, params.Get(updatedBeforeQueryKey)); err == nil {
		qf.UpdatedBefore = &t
	}

	if t, err := time.Parse(time.RFC3339Nano, params.Get(updatedAfterQueryKey)); err == nil {
		qf.UpdatedAfter = &t
	}

	if i, err := strconv.ParseBool(params.Get(includeArchivedQueryKey)); err == nil {
		qf.IncludeArchived = &i
	}

	switch strings.ToLower(params.Get(sortByQueryKey)) {
	case "asc":
		qf.SortBy = SortAscending
	case "desc":
		qf.SortBy = SortDescending
	}
}

// SetPage sets the current page with certain constraints.
func (qf *QueryFilter) SetPage(page *uint16) {
	if page != nil {
		qf.Page = pointer.To(uint16(math.Max(1, float64(*page))))
	}
}

// QueryOffset calculates a query page from the current filter values.
func (qf *QueryFilter) QueryOffset() uint16 {
	if qf != nil && qf.Limit != nil && qf.Page != nil {
		return uint16(*qf.Limit) * (*qf.Page - 1)
	}
	return 0
}

// ToValues returns a url.Values from a QueryFilter.
func (qf *QueryFilter) ToValues() url.Values {
	if qf == nil {
		return DefaultQueryFilter().ToValues()
	}

	v := url.Values{}

	if qf.Page != nil {
		v.Set(pageQueryKey, strconv.FormatUint(uint64(*qf.Page), 10))
	}

	if qf.Limit != nil {
		v.Set(LimitQueryKey, strconv.FormatUint(uint64(*qf.Limit), 10))
	}

	if qf.SortBy != nil {
		v.Set(sortByQueryKey, *qf.SortBy)
	}

	if qf.CreatedBefore != nil {
		v.Set(createdBeforeQueryKey, qf.CreatedBefore.Format(time.RFC3339Nano))
	}

	if qf.CreatedAfter != nil {
		v.Set(createdAfterQueryKey, qf.CreatedAfter.Format(time.RFC3339Nano))
	}

	if qf.UpdatedBefore != nil {
		v.Set(updatedBeforeQueryKey, qf.UpdatedBefore.Format(time.RFC3339Nano))
	}

	if qf.UpdatedAfter != nil {
		v.Set(updatedAfterQueryKey, qf.UpdatedAfter.Format(time.RFC3339Nano))
	}

	if qf.IncludeArchived != nil {
		v.Set(includeArchivedQueryKey, strconv.FormatBool(*qf.IncludeArchived))
	}

	return v
}

// ToPagination returns a Pagination from a QueryFilter.
func (qf *QueryFilter) ToPagination() Pagination {
	if qf == nil {
		return DefaultQueryFilter().ToPagination()
	}

	x := Pagination{}

	if qf.Page != nil {
		x.Page = *qf.Page
	}

	if qf.Limit != nil {
		x.Limit = *qf.Limit
	}

	return x
}

// ExtractQueryFilterFromRequest can extract a QueryFilter from a request.
func ExtractQueryFilterFromRequest(req *http.Request) *QueryFilter {
	qf := DefaultQueryFilter()
	qf.FromParams(req.URL.Query())

	if qf.Limit != nil {
		if *qf.Limit == 0 {
			qf.Limit = pointer.To(uint8(DefaultLimit))
		}
	}

	return qf
}
