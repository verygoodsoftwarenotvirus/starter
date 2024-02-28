package fakes

import (
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/pointer"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// BuildFleshedOutQueryFilter builds a fully fleshed out QueryFilter.
func BuildFleshedOutQueryFilter() *types.QueryFilter {
	return &types.QueryFilter{
		Page:          pointer.To(uint16(10)),
		Limit:         pointer.To(uint8(20)),
		CreatedAfter:  pointer.To(BuildFakeTime()),
		CreatedBefore: pointer.To(BuildFakeTime()),
		UpdatedAfter:  pointer.To(BuildFakeTime()),
		UpdatedBefore: pointer.To(BuildFakeTime()),
		SortBy:        types.SortAscending,
	}
}
