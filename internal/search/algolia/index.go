package algolia

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
)

var (
	// ErrEmptyQueryProvided indicates an empty query was provided as input.
	ErrEmptyQueryProvided = errors.New("empty search query provided")
)

// Index implements our indexManager interface.
func (m *indexManager[T]) Index(ctx context.Context, id string, value any) error {
	_, span := m.tracer.StartSpan(ctx)
	defer span.End()

	logger := m.logger.WithValue("id", id).WithValue("value", value)
	logger.Debug("adding to index")

	jsonEncoded, err := json.Marshal(value)
	if err != nil {
		return err
	}

	var newValue map[string]any
	if unmarshalErr := json.Unmarshal(jsonEncoded, &newValue); unmarshalErr != nil {
		return unmarshalErr
	}

	// we make a huge, albeit safe assumption here.
	newValue["objectID"] = newValue["id"]
	delete(newValue, "id")

	if _, err = m.client.SaveObject(newValue); err != nil {
		return err
	}

	return nil
}

// Search implements our indexManager interface.
func (m *indexManager[T]) Search(ctx context.Context, query string) ([]*T, error) {
	_, span := m.tracer.StartSpan(ctx)
	defer span.End()

	tracing.AttachToSpan(span, keys.SearchQueryKey, query)
	logger := m.logger.WithValue(keys.SearchQueryKey, query)

	if query == "" {
		return nil, ErrEmptyQueryProvided
	}

	res, searchErr := m.client.Search(query)
	if searchErr != nil {
		return nil, searchErr
	}

	results := []*T{}
	for _, hit := range res.Hits {
		var x *T

		// we make the same assumption here, sort of
		if _, ok := hit["objectID"]; ok {
			hit["id"] = hit["objectID"]
			delete(hit, "objectID")
		}

		var encodedAsJSON []byte
		encodedAsJSON, err := json.Marshal(hit)
		if err != nil {
			return nil, err
		}

		if unmarshalErr := json.Unmarshal(encodedAsJSON, &x); unmarshalErr != nil {
			return nil, unmarshalErr
		}

		results = append(results, x)
	}

	logger.Debug("search performed")

	return results, nil
}

// Delete implements our indexManager interface.
func (m *indexManager[T]) Delete(ctx context.Context, id string) error {
	_, span := m.tracer.StartSpan(ctx)
	defer span.End()

	logger := m.logger.WithValue("id", id)

	if _, err := m.client.DeleteObject(id); err != nil {
		return err
	}

	logger.Debug("removed from index")

	return nil
}

// Wipe implements our indexManager interface.
func (m *indexManager[T]) Wipe(ctx context.Context) error {
	_, span := m.tracer.StartSpan(ctx)
	defer span.End()

	if _, err := m.client.ClearObjects(); err != nil {
		return err
	}

	return nil
}
