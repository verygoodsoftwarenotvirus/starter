package converters

import (
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// ConvertAuditLogEntryToAuditLogEntryDatabaseCreationInput builds a AuditLogEntryDatabaseCreationInput from a AuditLogEntry.
func ConvertAuditLogEntryToAuditLogEntryDatabaseCreationInput(x *types.AuditLogEntry) *types.AuditLogEntryDatabaseCreationInput {
	v := &types.AuditLogEntryDatabaseCreationInput{
		Changes:          x.Changes,
		BelongsToAccount: x.BelongsToAccount,
		ID:               x.ID,
		ResourceType:     x.ResourceType,
		RelevantID:       x.RelevantID,
		EventType:        x.EventType,
		BelongsToUser:    x.BelongsToUser,
	}

	return v
}
