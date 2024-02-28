package config

import (
	"context"
	"strings"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search/algolia"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search/elasticsearch"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	// ElasticsearchProvider represents the elasticsearch search index provider.
	ElasticsearchProvider = "elasticsearch"
	// AlgoliaProvider represents the algolia search index provider.
	AlgoliaProvider = "algolia"
)

// Config contains settings regarding search indices.
type Config struct {
	_ struct{} `json:"-"`

	Algolia       *algolia.Config       `json:"algolia"       toml:"algolia,omitempty"`
	Elasticsearch *elasticsearch.Config `json:"elasticsearch" toml:"elasticsearch,omitempty"`
	Provider      string                `json:"provider"      toml:"provider,omitempty"`
}

var _ validation.ValidatableWithContext = (*Config)(nil)

// ValidateWithContext validates a Config struct.
func (cfg *Config) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, cfg,
		validation.Field(&cfg.Provider, validation.In(ElasticsearchProvider, AlgoliaProvider)),
		validation.Field(&cfg.Algolia, validation.When(cfg.Provider == AlgoliaProvider, validation.Required)),
		validation.Field(&cfg.Elasticsearch, validation.When(cfg.Provider == ElasticsearchProvider, validation.Required)),
	)
}

// ProvideIndex validates a Config struct.
func ProvideIndex[T search.Searchable](ctx context.Context, logger logging.Logger, tracerProvider tracing.TracerProvider, cfg *Config, indexName string) (search.Index[T], error) {
	switch strings.TrimSpace(strings.ToLower(cfg.Provider)) {
	case ElasticsearchProvider:
		return elasticsearch.ProvideIndexManager[T](ctx, logger, tracerProvider, cfg.Elasticsearch, indexName)
	case AlgoliaProvider:
		return algolia.ProvideIndexManager[T](ctx, logger, tracerProvider, cfg.Algolia, indexName)
	default:
		return &search.NoopIndexManager[T]{}, nil
	}
}
