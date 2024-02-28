package types

type (
	// ServiceEventType enumerates valid service event types.
	ServiceEventType string

	// DataChangeMessage represents an event that asks a worker to write data to the datastore.
	DataChangeMessage struct {
		_ struct{} `json:"-"`

		AccountInvitation           *AccountInvitation           `json:"accountInvitation,omitempty"`
		Context                     map[string]any               `json:"context,omitempty"`
		Account                     *Account                     `json:"account,omitempty"`
		Webhook                     *Webhook                     `json:"webhook,omitempty"`
		UserMembership              *AccountUserMembership       `json:"userMembership,omitempty"`
		PasswordResetToken          *PasswordResetToken          `json:"passwordResetToken,omitempty"`
		ServiceSetting              *ServiceSetting              `json:"serviceSetting,omitempty"`
		ServiceSettingConfiguration *ServiceSettingConfiguration `json:"serviceSettingConfiguration,omitempty"`
		UserNotification            *UserNotification            `json:"userNotification,omitempty"`
		UserNotificationID          string                       `json:"userNotificationID"`
		AccountInvitationID         string                       `json:"accountInvitationID,omitempty"`
		UserID                      string                       `json:"userID"`
		AccountID                   string                       `json:"accountID,omitempty"`
		EventType                   ServiceEventType             `json:"messageType"`
		EmailVerificationToken      string                       `json:"emailVerificationToken,omitempty"`
		OAuth2ClientID              string                       `json:"oauth2ClientID,omitempty"`
	}

	// ChoreMessage represents an event that asks a worker to perform a chore.
	ChoreMessage struct {
		_ struct{} `json:"-"`

		ChoreType string `json:"choreType"`
	}
)
