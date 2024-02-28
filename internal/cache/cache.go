package cache

import (
	"context"
	"errors"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

var (
	ErrNotFound = errors.New("not found")
)

type (
	Cacheable interface {
		types.SessionContextData
	}

	// Cache is our wrapper interface for a cache.
	Cache[T Cacheable] interface {
		Get(ctx context.Context, key string) (*T, error)
		Set(ctx context.Context, key string, value *T) error
		Delete(ctx context.Context, key string) error
	}
)
