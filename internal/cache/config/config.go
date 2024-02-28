package config

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/cache"
	"github.com/verygoodsoftwarenotvirus/starter/internal/cache/memory"
	"github.com/verygoodsoftwarenotvirus/starter/internal/cache/redis"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	// ProviderMemory is the memory provider.
	ProviderMemory = "memory"
	// ProviderRedis is the redis provider.
	ProviderRedis = "redis"
)

type (
	// Config is the configuration for the cache.
	Config struct {
		Memory   struct{}      `json:"memory"   toml:"memory"`
		Redis    *redis.Config `json:"redis"    toml:"redis"`
		Provider string        `json:"provider" toml:"provider"`
	}
)

var _ validation.ValidatableWithContext = (*Config)(nil)

// ValidateWithContext validates a Config struct.
func (cfg *Config) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, cfg,
		validation.Field(&cfg.Provider, validation.In(ProviderMemory, ProviderRedis)),
		validation.Field(&cfg.Memory, validation.When(cfg.Provider == ProviderMemory, validation.Required)),
		validation.Field(&cfg.Redis, validation.When(cfg.Provider == ProviderRedis, validation.Required)),
	)
}

// ProvideCache provides a Cache.
func ProvideCache[T cache.Cacheable](cfg *Config) (cache.Cache[T], error) {
	switch strings.TrimSpace(strings.ToLower(cfg.Provider)) {
	case ProviderMemory:
		return memory.NewInMemoryCache[T](), nil
	case ProviderRedis:
		return redis.NewRedisCache[T](cfg.Redis, time.Hour), nil
	default:
		return nil, fmt.Errorf("invalid cache provider: %q", cfg.Provider)
	}
}
