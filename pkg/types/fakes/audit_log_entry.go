package fakes

import (
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// BuildFakeAuditLogEntry builds a faked valid instrument.
func BuildFakeAuditLogEntry() *types.AuditLogEntry {
	return &types.AuditLogEntry{
		ID:               BuildFakeID(),
		CreatedAt:        BuildFakeTime(),
		Changes:          nil,
		BelongsToAccount: nil,
		ResourceType:     "example",
		RelevantID:       BuildFakeID(),
		EventType:        types.AuditLogEventTypeOther,
		BelongsToUser:    BuildFakeID(),
	}
}

// BuildFakeAuditLogEntryList builds a faked AuditLogEntryList.
func BuildFakeAuditLogEntryList() *types.QueryFilteredResult[types.AuditLogEntry] {
	var examples []*types.AuditLogEntry
	for i := 0; i < exampleQuantity; i++ {
		examples = append(examples, BuildFakeAuditLogEntry())
	}

	return &types.QueryFilteredResult[types.AuditLogEntry]{
		Pagination: types.Pagination{
			Page:          1,
			Limit:         50,
			FilteredCount: exampleQuantity / 2,
			TotalCount:    exampleQuantity,
		},
		Data: examples,
	}
}
