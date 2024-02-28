package search

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	// IndexTypeUsers represents the users index.
	IndexTypeUsers = "users"
)

type (
	Searchable interface {
		types.UserSearchSubset
	}

	// IndexSearcher is our wrapper interface for querying a text search index.
	IndexSearcher[T Searchable] interface {
		Search(ctx context.Context, query string) (ids []*T, err error)
	}

	// IndexManager is our wrapper interface for a text search index.
	IndexManager interface {
		Index(ctx context.Context, id string, value any) error
		Delete(ctx context.Context, id string) (err error)
		Wipe(ctx context.Context) error
	}

	// Index is our wrapper interface for a text search index.
	Index[T Searchable] interface {
		IndexSearcher[T]
		IndexManager
	}
)
