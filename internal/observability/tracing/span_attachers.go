package tracing

import (
	"fmt"
	"net/http"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/mssola/useragent"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

func keyValueForValue(k string, x any) attribute.KeyValue {
	if x == nil {
		return attribute.String(k, "nil")
	}

	switch v := x.(type) {
	case bool:
		return attribute.Bool(k, v)
	case []bool:
		return attribute.BoolSlice(k, v)
	case int:
		return attribute.Int(k, v)
	case []int:
		return attribute.IntSlice(k, v)
	case uint8:
		return attribute.Int64(k, int64(v))
	case uint16:
		return attribute.Int64(k, int64(v))
	case uint32:
		return attribute.Int64(k, int64(v))
	case uint64:
		return attribute.String(k, fmt.Sprintf("%d", v))
	case int64:
		return attribute.Int64(k, v)
	case []int64:
		return attribute.Int64Slice(k, v)
	case float64:
		return attribute.Float64(k, v)
	case []float64:
		return attribute.Float64Slice(k, v)
	case string:
		return attribute.String(k, v)
	case []string:
		return attribute.StringSlice(k, v)
	case time.Time:
		return attribute.String(k, v.Format(time.RFC3339Nano))
	case fmt.Stringer:
		return attribute.Stringer(k, v)
	default:
		return attribute.String(k, fmt.Sprintf("%+v", x))
	}
}

func AttachToSpan[T any](span trace.Span, attachmentKey string, x T) {
	if span != nil {
		span.SetAttributes(keyValueForValue(attachmentKey, x))
	}
}

// AttachFilterDataToSpan provides a consistent way to attach a filter's info to a span.
func AttachFilterDataToSpan(span trace.Span, page *uint16, limit *uint8, sortBy *string) {
	if page != nil {
		AttachToSpan(span, keys.FilterPageKey, *page)
	}

	if limit != nil {
		AttachToSpan(span, keys.FilterLimitKey, *limit)
	}

	if sortBy != nil {
		AttachToSpan(span, keys.FilterSortByKey, *sortBy)
	}
}

// AttachSessionContextDataToSpan provides a consistent way to attach a SessionContextData object to a span.
func AttachSessionContextDataToSpan(span trace.Span, sessionCtxData *types.SessionContextData) {
	if sessionCtxData != nil {
		AttachToSpan(span, keys.RequesterIDKey, sessionCtxData.Requester.UserID)
		AttachToSpan(span, keys.ActiveAccountIDKey, sessionCtxData.ActiveAccountID)
		if sessionCtxData.Requester.ServicePermissions != nil {
			AttachToSpan(span, keys.UserIsServiceAdminKey, sessionCtxData.Requester.ServicePermissions.IsServiceAdmin())
		}
	}
}

// AttachUserToSpan provides a consistent way to attach a user to a span.
func AttachUserToSpan(span trace.Span, user *types.User) {
	if user != nil {
		AttachToSpan(span, keys.UserIDKey, user.ID)
		AttachToSpan(span, keys.UsernameKey, user.Username)
	}
}

// AttachRequestToSpan attaches a given HTTP request to a span.
func AttachRequestToSpan(span trace.Span, req *http.Request) {
	if req != nil {
		AttachToSpan(span, keys.RequestURIKey, req.URL.String())
		AttachToSpan(span, keys.RequestMethodKey, req.Method)
		AttachUserAgentDataToSpan(span, req)

		for k, v := range req.Header {
			AttachToSpan(span, fmt.Sprintf("%s.%s", keys.RequestHeadersKey, k), v)
		}
	}
}

// AttachResponseToSpan attaches a given *http.Response to a span.
func AttachResponseToSpan(span trace.Span, res *http.Response) {
	if res != nil {
		AttachRequestToSpan(span, res.Request)
		span.SetAttributes(attribute.Int(keys.ResponseStatusKey, res.StatusCode))

		for k, v := range res.Header {
			AttachToSpan(span, fmt.Sprintf("%s.%s", keys.ResponseHeadersKey, k), v)
		}
	}
}

// AttachErrorToSpan attaches a given error to a span.
func AttachErrorToSpan(span trace.Span, description string, err error) {
	if err != nil {
		span.SetStatus(codes.Error, description)
		span.RecordError(
			err,
			trace.WithStackTrace(true),
			trace.WithTimestamp(time.Now()),
			trace.WithAttributes(attribute.String("error.description", description)),
		)
	}
}

// AttachQueryFilterToSpan attaches a given query filter to a span.
func AttachQueryFilterToSpan(span trace.Span, filter *types.QueryFilter) {
	if filter != nil {
		if filter.Limit != nil {
			AttachToSpan(span, keys.FilterLimitKey, *filter.Limit)
		}

		if filter.Page != nil {
			AttachToSpan(span, keys.FilterPageKey, *filter.Page)
		}

		if filter.CreatedAfter != nil {
			AttachToSpan(span, keys.FilterCreatedAfterKey, *filter.CreatedAfter)
		}

		if filter.CreatedBefore != nil {
			AttachToSpan(span, keys.FilterCreatedBeforeKey, *filter.CreatedBefore)
		}

		if filter.UpdatedAfter != nil {
			AttachToSpan(span, keys.FilterUpdatedAfterKey, *filter.UpdatedAfter)
		}

		if filter.UpdatedBefore != nil {
			AttachToSpan(span, keys.FilterUpdatedBeforeKey, *filter.UpdatedBefore)
		}

		if filter.SortBy != nil {
			AttachToSpan(span, keys.FilterSortByKey, *filter.SortBy)
		}
	} else {
		AttachToSpan(span, keys.FilterIsNilKey, true)
	}
}

// AttachUserAgentDataToSpan attaches a given search query to a span.
func AttachUserAgentDataToSpan(span trace.Span, req *http.Request) {
	header := req.Header.Get("User-Agent")
	ua := useragent.New(header)

	if ua != nil {
		AttachToSpan(span, keys.UserAgentOSKey, ua.OS())
		AttachToSpan(span, keys.UserAgentMobileKey, ua.Mobile())
		AttachToSpan(span, keys.UserAgentBotKey, ua.Bot())
	}
}
