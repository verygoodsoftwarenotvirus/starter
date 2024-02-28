package types

import (
	"context"
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// AdminService describes a structure capable of serving traffic related to users.
	AdminService interface {
		UserAccountStatusChangeHandler(http.ResponseWriter, *http.Request)
	}

	// UserAccountStatusUpdateInput represents what an admin User could provide as input for changing statuses.
	UserAccountStatusUpdateInput struct {
		_ struct{} `json:"-"`

		NewStatus    string `json:"newStatus"`
		Reason       string `json:"reason"`
		TargetUserID string `json:"targetUserID"`
	}

	// FrontendService serves static frontend files.
	FrontendService interface {
		StaticDir(ctx context.Context, staticFilesDirectory string) (http.HandlerFunc, error)
	}
)

var _ validation.ValidatableWithContext = (*UserAccountStatusUpdateInput)(nil)

// ValidateWithContext ensures our struct is validatable.
func (i *UserAccountStatusUpdateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, i,
		validation.Field(&i.NewStatus, validation.Required),
		validation.Field(&i.Reason, validation.Required),
		validation.Field(&i.TargetUserID, validation.Required),
	)
}
