package codegen

import (
	"reflect"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

type TypeDefinition struct {
	Type        any
	Description string
}

func (d *TypeDefinition) Name() string {
	n := reflect.Indirect(reflect.ValueOf(d.Type)).Type().Name()
	return n
}

var (
	CustomTypeMap = map[string]string{}

	DefaultEnumValues = map[string]string{}

	TypeDefinitionFilesToGenerate = map[string][]any{
		"admin": {
			types.ModifyUserPermissionsInput{},
		},
		"oauth2Clients": {
			types.OAuth2Client{},
			types.OAuth2ClientCreationRequestInput{},
			types.OAuth2ClientCreationResponse{},
		},
		"auth": {
			types.ChangeActiveAccountInput{},
			types.PasswordResetToken{},
			types.PasswordResetTokenCreationRequestInput{},
			types.PasswordResetTokenRedemptionRequestInput{},
			types.TOTPSecretRefreshInput{},
			types.TOTPSecretVerificationInput{},
			types.TOTPSecretRefreshResponse{},
			types.PasswordUpdateInput{},
		},
		"errors": {
			types.APIError{},
		},
		"accountInvitations": {
			types.AccountInvitation{},
			types.AccountInvitationUpdateRequestInput{},
			types.AccountInvitationCreationRequestInput{},
		},
		"accounts": {
			types.Account{},
			types.AccountCreationRequestInput{},
			types.AccountUpdateRequestInput{},
			types.AccountOwnershipTransferInput{},
		},
		"accountUserMemberships": {
			types.AccountUserMembership{},
			types.AccountUserMembershipWithUser{},
			types.AccountUserMembershipCreationRequestInput{},
		},
		"permissions": {
			types.UserPermissionsRequestInput{},
			types.UserPermissionsResponse{},
		},
		"users": {
			types.UserStatusResponse{},
			types.User{},
			types.UserRegistrationInput{},
			types.UserCreationResponse{},
			types.UserLoginInput{},
			types.UsernameReminderRequestInput{},
			types.UserAccountStatusUpdateInput{},
			types.EmailAddressVerificationRequestInput{},
			types.AvatarUpdateInput{},
		},
		"serviceSetting": {
			types.ServiceSetting{},
			types.ServiceSettingCreationRequestInput{},
			types.ServiceSettingUpdateRequestInput{},
		},
		"serviceSettingConfiguration": {
			types.ServiceSettingConfiguration{},
			types.ServiceSettingConfigurationCreationRequestInput{},
			types.ServiceSettingConfigurationUpdateRequestInput{},
		},
		"webhooks": {
			types.Webhook{},
			types.WebhookTriggerEvent{},
			types.WebhookCreationRequestInput{},
		},
	}

	TypesWeCareAbout = []*TypeDefinition{
		{
			Type:        &types.ModifyUserPermissionsInput{},
			Description: "",
		},
		{
			Type:        &types.OAuth2Client{},
			Description: "",
		},
		{
			Type:        &types.OAuth2ClientCreationRequestInput{},
			Description: "",
		},
		{
			Type:        &types.OAuth2ClientCreationResponse{},
			Description: "",
		},
		{
			Type:        &types.ChangeActiveAccountInput{},
			Description: "",
		},
		{
			Type:        &types.PasswordResetToken{},
			Description: "",
		},
		{
			Type:        &types.PasswordResetTokenCreationRequestInput{},
			Description: "",
		},
		{
			Type:        &types.PasswordResetTokenRedemptionRequestInput{},
			Description: "",
		},
		{
			Type:        &types.TOTPSecretRefreshInput{},
			Description: "",
		},
		{
			Type:        &types.TOTPSecretVerificationInput{},
			Description: "",
		},
		{
			Type:        &types.TOTPSecretRefreshResponse{},
			Description: "",
		},
		{
			Type:        &types.PasswordUpdateInput{},
			Description: "",
		},
		{
			Type:        &types.APIError{},
			Description: "",
		},
		{
			Type:        &types.AccountInvitation{},
			Description: "",
		},
		{
			Type:        &types.AccountInvitationUpdateRequestInput{},
			Description: "",
		},
		{
			Type:        &types.AccountInvitationCreationRequestInput{},
			Description: "",
		},
		{
			Type:        &types.Account{},
			Description: "",
		},
		{
			Type:        &types.AccountCreationRequestInput{},
			Description: "",
		},
		{
			Type:        &types.AccountUpdateRequestInput{},
			Description: "",
		},
		{
			Type:        &types.AccountOwnershipTransferInput{},
			Description: "",
		},
		{
			Type:        &types.AccountUserMembership{},
			Description: "",
		},
		{
			Type:        &types.AccountUserMembershipWithUser{},
			Description: "",
		},
		{
			Type:        &types.AccountUserMembershipCreationRequestInput{},
			Description: "",
		},
		{
			Type:        &types.UserPermissionsRequestInput{},
			Description: "",
		},
		{
			Type:        &types.UserPermissionsResponse{},
			Description: "",
		},
		{
			Type:        &types.UserStatusResponse{},
			Description: "",
		},
		{
			Type:        &types.User{},
			Description: "",
		},
		{
			Type:        &types.UserRegistrationInput{},
			Description: "",
		},
		{
			Type:        &types.UserCreationResponse{},
			Description: "",
		},
		{
			Type:        &types.UserLoginInput{},
			Description: "",
		},
		{
			Type:        &types.UsernameReminderRequestInput{},
			Description: "",
		},
		{
			Type:        &types.UserAccountStatusUpdateInput{},
			Description: "",
		},
		{
			Type:        &types.EmailAddressVerificationRequestInput{},
			Description: "",
		},
		{
			Type:        &types.AvatarUpdateInput{},
			Description: "",
		},
		{
			Type:        &types.ServiceSetting{},
			Description: "",
		},
		{
			Type:        &types.ServiceSettingCreationRequestInput{},
			Description: "",
		},
		{
			Type:        &types.ServiceSettingUpdateRequestInput{},
			Description: "",
		},
		{
			Type:        &types.ServiceSettingConfiguration{},
			Description: "",
		},
		{
			Type:        &types.ServiceSettingConfigurationCreationRequestInput{},
			Description: "",
		},
		{
			Type:        &types.ServiceSettingConfigurationUpdateRequestInput{},
			Description: "",
		},
		{
			Type:        &types.Webhook{},
			Description: "",
		},
		{
			Type:        &types.WebhookTriggerEvent{},
			Description: "",
		},
		{
			Type:        &types.WebhookCreationRequestInput{},
			Description: "",
		},
	}
)
