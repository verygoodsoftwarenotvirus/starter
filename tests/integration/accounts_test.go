package integration

import (
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/apiclient"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"
	testutils "github.com/verygoodsoftwarenotvirus/starter/tests/utils"

	"github.com/brianvoe/gofakeit/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func checkAccountEquality(t *testing.T, expected, actual *types.Account) {
	t.Helper()

	assert.NotZero(t, actual.ID)
	assert.Equal(t, expected.Name, actual.Name, "expected Name for account %s to be %v, but it was %v ", expected.ID, expected.Name, actual.Name)
	assert.Equal(t, expected.AddressLine1, actual.AddressLine1, "expected AddressLine1 for account %s to be %v, but it was %v", expected.ID, expected.AddressLine1, actual.AddressLine1)
	assert.Equal(t, expected.AddressLine2, actual.AddressLine2, "expected AddressLine2 for account %s to be %v, but it was %v", expected.ID, expected.AddressLine2, actual.AddressLine2)
	assert.Equal(t, expected.City, actual.City, "expected City for account %s to be %v, but it was %v", expected.ID, expected.City, actual.City)
	assert.Equal(t, expected.State, actual.State, "expected State for account %s to be %v, but it was %v", expected.ID, expected.State, actual.State)
	assert.Equal(t, expected.ZipCode, actual.ZipCode, "expected ZipCode for account %s to be %v, but it was %v", expected.ID, expected.ZipCode, actual.ZipCode)
	assert.Equal(t, expected.Country, actual.Country, "expected Country for account %s to be %v, but it was %v", expected.ID, expected.Country, actual.Country)
	assert.Equal(t, expected.Latitude, actual.Latitude, "expected Latitude for account %s to be %v, but it was %v", expected.ID, expected.Latitude, actual.Latitude)
	assert.Equal(t, expected.Longitude, actual.Longitude, "expected Longitude for account %s to be %v, but it was %v", expected.ID, expected.Longitude, actual.Longitude)
	assert.NotZero(t, actual.CreatedAt)
}

func (s *TestSuite) TestAccounts_Creating() {
	s.runForEachClient("should be possible to create accounts", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Create account.
			exampleAccount := fakes.BuildFakeAccount()
			exampleAccountInput := converters.ConvertAccountToAccountCreationRequestInput(exampleAccount)
			createdAccount, err := testClients.user.CreateAccount(ctx, exampleAccountInput)
			requireNotNilAndNoProblems(t, createdAccount, err)

			// Assert account equality.
			checkAccountEquality(t, exampleAccount, createdAccount)

			// Clean up.
			assert.NoError(t, testClients.user.ArchiveAccount(ctx, createdAccount.ID))
		}
	})
}

func (s *TestSuite) TestAccounts_Listing() {
	s.runForEachClient("should be possible to list accounts", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Create accounts.
			var expected []*types.Account
			for i := 0; i < 5; i++ {
				// Create account.
				exampleAccount := fakes.BuildFakeAccount()
				exampleAccountInput := converters.ConvertAccountToAccountCreationRequestInput(exampleAccount)
				createdAccount, accountCreationErr := testClients.user.CreateAccount(ctx, exampleAccountInput)
				requireNotNilAndNoProblems(t, createdAccount, accountCreationErr)

				expected = append(expected, createdAccount)
			}

			// Assert account list equality.
			actual, err := testClients.user.GetAccounts(ctx, nil)
			requireNotNilAndNoProblems(t, actual, err)
			assert.True(
				t,
				len(expected) <= len(actual.Data),
				"expected %d to be <= %d",
				len(expected),
				len(actual.Data),
			)

			// Clean up.
			for _, createdAccount := range actual.Data {
				assert.NoError(t, testClients.user.ArchiveAccount(ctx, createdAccount.ID))
			}
		}
	})
}

func (s *TestSuite) TestAccounts_Reading_Returns404ForNonexistentAccount() {
	s.runForEachClient("should not be possible to read a non-existent account", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Attempt to fetch nonexistent account.
			_, err := testClients.user.GetAccount(ctx, nonexistentID)
			assert.Error(t, err)
		}
	})
}

func (s *TestSuite) TestAccounts_Reading() {
	s.runForEachClient("should be possible to read a account", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Create account.
			exampleAccount := fakes.BuildFakeAccount()
			exampleAccountInput := converters.ConvertAccountToAccountCreationRequestInput(exampleAccount)
			createdAccount, err := testClients.user.CreateAccount(ctx, exampleAccountInput)
			requireNotNilAndNoProblems(t, createdAccount, err)

			// Fetch account.
			actual, err := testClients.user.GetAccount(ctx, createdAccount.ID)
			requireNotNilAndNoProblems(t, actual, err)

			// Assert account equality.
			checkAccountEquality(t, exampleAccount, actual)

			// Clean up account.
			assert.NoError(t, testClients.user.ArchiveAccount(ctx, createdAccount.ID))
		}
	})
}

func (s *TestSuite) TestAccounts_Updating_Returns404ForNonexistentAccount() {
	s.runForEachClient("should not be possible to update a non-existent account", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			exampleAccount := fakes.BuildFakeAccount()
			exampleAccount.ID = nonexistentID

			assert.Error(t, testClients.user.UpdateAccount(ctx, exampleAccount))
		}
	})
}

func (s *TestSuite) TestAccounts_Updating() {
	s.runForEachClient("should be possible to update a account", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Create account.
			exampleAccount := fakes.BuildFakeAccount()
			exampleAccountInput := converters.ConvertAccountToAccountCreationRequestInput(exampleAccount)
			createdAccount, err := testClients.user.CreateAccount(ctx, exampleAccountInput)
			requireNotNilAndNoProblems(t, createdAccount, err)

			// Change account.
			createdAccount.Update(converters.ConvertAccountToAccountUpdateRequestInput(exampleAccount))
			assert.NoError(t, testClients.user.UpdateAccount(ctx, createdAccount))

			// Fetch account.
			actual, err := testClients.user.GetAccount(ctx, createdAccount.ID)
			requireNotNilAndNoProblems(t, actual, err)

			// Assert account equality.
			checkAccountEquality(t, exampleAccount, actual)
			assert.NotNil(t, actual.LastUpdatedAt)

			// Clean up account.
			assert.NoError(t, testClients.user.ArchiveAccount(ctx, createdAccount.ID))
		}
	})
}

func (s *TestSuite) TestAccounts_Archiving() {
	s.runForEachClient("should be possible to archive a account", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Create account.
			exampleAccount := fakes.BuildFakeAccount()
			exampleAccountInput := converters.ConvertAccountToAccountCreationRequestInput(exampleAccount)
			createdAccount, err := testClients.user.CreateAccount(ctx, exampleAccountInput)
			requireNotNilAndNoProblems(t, createdAccount, err)

			// Clean up account.
			assert.NoError(t, testClients.user.ArchiveAccount(ctx, createdAccount.ID))
		}
	})
}

func (s *TestSuite) TestAccounts_InvitingPreExistentUser() {
	s.runForEachClient("should be possible to invite an already-registered user", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			currentStatus, statusErr := testClients.user.UserStatus(s.ctx)
			requireNotNilAndNoProblems(t, currentStatus, statusErr)
			relevantAccountID := currentStatus.ActiveAccount

			// Create webhook.
			exampleWebhook := fakes.BuildFakeWebhook()
			exampleWebhookInput := converters.ConvertWebhookToWebhookCreationRequestInput(exampleWebhook)
			createdWebhook, err := testClients.user.CreateWebhook(ctx, exampleWebhookInput)
			require.NoError(t, err)

			checkWebhookEquality(t, exampleWebhook, createdWebhook)

			createdWebhook, err = testClients.user.GetWebhook(ctx, createdWebhook.ID)
			requireNotNilAndNoProblems(t, createdWebhook, err)
			require.Equal(t, relevantAccountID, createdWebhook.BelongsToAccount)

			u, _, c, _ := createUserAndClientForTest(ctx, t, nil)

			invitation, err := testClients.user.InviteUserToAccount(ctx, relevantAccountID, &types.AccountInvitationCreationRequestInput{
				Note:    t.Name(),
				ToName:  t.Name(),
				ToEmail: u.EmailAddress,
			})
			require.NoError(t, err)

			sentInvitations, err := testClients.user.GetPendingAccountInvitationsFromUser(ctx, nil)
			requireNotNilAndNoProblems(t, sentInvitations, err)
			assert.NotEmpty(t, sentInvitations.Data)

			invitations, err := c.GetPendingAccountInvitationsForUser(ctx, nil)
			requireNotNilAndNoProblems(t, invitations, err)
			assert.NotEmpty(t, invitations.Data)

			err = c.AcceptAccountInvitation(ctx, invitation.ID, invitation.Token, t.Name())
			require.NoError(t, err)

			sentInvitations, err = testClients.user.GetPendingAccountInvitationsFromUser(ctx, nil)
			requireNotNilAndNoProblems(t, sentInvitations, err)
			assert.Empty(t, sentInvitations.Data)

			accounts, err := c.GetAccounts(ctx, nil)

			var found bool
			for _, account := range accounts.Data {
				if !found {
					found = account.ID == relevantAccountID
				}
			}

			require.True(t, found)
			require.NoError(t, c.SwitchActiveAccount(ctx, relevantAccountID))

			_, err = c.GetWebhook(ctx, createdWebhook.ID)
			require.NoError(t, err)
		}
	})
}

func (s *TestSuite) TestAccounts_InvitingUserWhoSignsUpIndependently() {
	s.runForEachClient("should be possible to invite a user before they sign up", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			currentStatus, statusErr := testClients.user.UserStatus(s.ctx)
			requireNotNilAndNoProblems(t, currentStatus, statusErr)
			relevantAccountID := currentStatus.ActiveAccount

			// Create webhook.
			exampleWebhook := fakes.BuildFakeWebhook()
			exampleWebhookInput := converters.ConvertWebhookToWebhookCreationRequestInput(exampleWebhook)
			createdWebhook, err := testClients.user.CreateWebhook(ctx, exampleWebhookInput)
			require.NoError(t, err)

			checkWebhookEquality(t, exampleWebhook, createdWebhook)

			createdWebhook, err = testClients.user.GetWebhook(ctx, createdWebhook.ID)
			requireNotNilAndNoProblems(t, createdWebhook, err)
			require.Equal(t, relevantAccountID, createdWebhook.BelongsToAccount)

			inviteReq := &types.AccountInvitationCreationRequestInput{
				Note:    t.Name(),
				ToEmail: gofakeit.Email(),
			}
			invitation, err := testClients.user.InviteUserToAccount(ctx, relevantAccountID, inviteReq)
			require.NoError(t, err)

			sentInvitations, err := testClients.user.GetPendingAccountInvitationsFromUser(ctx, nil)
			requireNotNilAndNoProblems(t, sentInvitations, err)
			assert.NotEmpty(t, sentInvitations.Data)

			_, _, c, _ := createUserAndClientForTest(ctx, t, &types.UserRegistrationInput{
				EmailAddress: inviteReq.ToEmail,
				Username:     fakes.BuildFakeUser().Username,
				Password:     gofakeit.Password(true, true, true, true, false, 64),
			})

			invitations, err := c.GetPendingAccountInvitationsForUser(ctx, nil)
			requireNotNilAndNoProblems(t, invitations, err)
			assert.NotEmpty(t, invitations.Data)

			err = c.AcceptAccountInvitation(ctx, invitation.ID, invitation.Token, t.Name())
			require.NoError(t, err)

			accounts, err := c.GetAccounts(ctx, nil)

			var found bool
			for _, account := range accounts.Data {
				if !found {
					found = account.ID == relevantAccountID
				}
			}

			require.True(t, found)
			require.NoError(t, c.SwitchActiveAccount(ctx, relevantAccountID))

			_, err = c.GetWebhook(ctx, createdWebhook.ID)
			require.NoError(t, err)

			sentInvitations, err = testClients.user.GetPendingAccountInvitationsFromUser(ctx, nil)
			requireNotNilAndNoProblems(t, sentInvitations, err)
			assert.Empty(t, sentInvitations.Data)
		}
	})
}

func (s *TestSuite) TestAccounts_InvitingUserWhoSignsUpIndependentlyAndThenCancelling() {
	s.runForEachClient("should be possible to invite a user before they sign up and cancel before they can accept", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			currentStatus, statusErr := testClients.user.UserStatus(s.ctx)
			requireNotNilAndNoProblems(t, currentStatus, statusErr)
			relevantAccountID := currentStatus.ActiveAccount

			// Create webhook.
			exampleWebhook := fakes.BuildFakeWebhook()
			exampleWebhookInput := converters.ConvertWebhookToWebhookCreationRequestInput(exampleWebhook)
			createdWebhook, err := testClients.user.CreateWebhook(ctx, exampleWebhookInput)
			require.NoError(t, err)

			checkWebhookEquality(t, exampleWebhook, createdWebhook)

			createdWebhook, err = testClients.user.GetWebhook(ctx, createdWebhook.ID)
			requireNotNilAndNoProblems(t, createdWebhook, err)
			require.Equal(t, relevantAccountID, createdWebhook.BelongsToAccount)

			inviteReq := &types.AccountInvitationCreationRequestInput{
				Note:    t.Name(),
				ToEmail: gofakeit.Email(),
			}
			invitation, err := testClients.user.InviteUserToAccount(ctx, relevantAccountID, inviteReq)
			require.NoError(t, err)

			sentInvitations, err := testClients.user.GetPendingAccountInvitationsFromUser(ctx, nil)
			requireNotNilAndNoProblems(t, sentInvitations, err)
			assert.NotEmpty(t, sentInvitations.Data)

			_, _, c, _ := createUserAndClientForTest(ctx, t, &types.UserRegistrationInput{
				EmailAddress: inviteReq.ToEmail,
				Username:     fakes.BuildFakeUser().Username,
				Password:     gofakeit.Password(true, true, true, true, false, 64),
			})

			invitations, err := c.GetPendingAccountInvitationsForUser(ctx, nil)
			requireNotNilAndNoProblems(t, invitations, err)
			assert.NotEmpty(t, invitations.Data)

			err = testClients.user.CancelAccountInvitation(ctx, invitation.ID, invitation.Token, t.Name())
			require.NoError(t, err)

			sentInvitations, err = testClients.user.GetPendingAccountInvitationsFromUser(ctx, nil)
			requireNotNilAndNoProblems(t, sentInvitations, err)
			assert.Empty(t, sentInvitations.Data)
		}
	})
}

func (s *TestSuite) TestAccounts_InvitingNewUserWithInviteLink() {
	s.runForEachClient("should be possible to invite a user via referral link", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			currentStatus, statusErr := testClients.user.UserStatus(s.ctx)
			requireNotNilAndNoProblems(t, currentStatus, statusErr)
			relevantAccountID := currentStatus.ActiveAccount

			// Create webhook.
			exampleWebhook := fakes.BuildFakeWebhook()
			exampleWebhookInput := converters.ConvertWebhookToWebhookCreationRequestInput(exampleWebhook)
			createdWebhook, err := testClients.user.CreateWebhook(ctx, exampleWebhookInput)
			require.NoError(t, err)

			checkWebhookEquality(t, exampleWebhook, createdWebhook)

			createdWebhook, err = testClients.user.GetWebhook(ctx, createdWebhook.ID)
			requireNotNilAndNoProblems(t, createdWebhook, err)
			require.Equal(t, relevantAccountID, createdWebhook.BelongsToAccount)

			inviteReq := &types.AccountInvitationCreationRequestInput{
				Note:    t.Name(),
				ToEmail: gofakeit.Email(),
			}
			createdInvitation, err := testClients.user.InviteUserToAccount(ctx, relevantAccountID, inviteReq)
			require.NoError(t, err)

			createdInvitation, err = testClients.user.GetAccountInvitation(ctx, relevantAccountID, createdInvitation.ID)
			requireNotNilAndNoProblems(t, createdInvitation, err)

			sentInvitations, err := testClients.user.GetPendingAccountInvitationsFromUser(ctx, nil)
			requireNotNilAndNoProblems(t, sentInvitations, err)
			assert.NotEmpty(t, sentInvitations.Data)

			_, _, c, _ := createUserAndClientForTest(ctx, t, &types.UserRegistrationInput{
				EmailAddress:    inviteReq.ToEmail,
				Username:        fakes.BuildFakeUser().Username,
				Password:        gofakeit.Password(true, true, true, true, false, 64),
				InvitationID:    createdInvitation.ID,
				InvitationToken: createdInvitation.Token,
			})

			accounts, err := c.GetAccounts(ctx, nil)
			require.NoError(t, err)

			var found bool
			for _, account := range accounts.Data {
				if !found {
					found = account.ID == relevantAccountID
				}
			}

			require.True(t, found)

			_, err = c.GetWebhook(ctx, createdWebhook.ID)
			require.NoError(t, err)
		}
	})
}

func (s *TestSuite) TestAccounts_InviteCanBeCancelled() {
	s.runForEachClient("should be possible to invite an already-registered user", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			currentStatus, statusErr := testClients.user.UserStatus(s.ctx)
			requireNotNilAndNoProblems(t, currentStatus, statusErr)
			relevantAccountID := currentStatus.ActiveAccount

			// Create webhook.
			exampleWebhook := fakes.BuildFakeWebhook()
			exampleWebhookInput := converters.ConvertWebhookToWebhookCreationRequestInput(exampleWebhook)
			createdWebhook, err := testClients.user.CreateWebhook(ctx, exampleWebhookInput)
			require.NoError(t, err)

			checkWebhookEquality(t, exampleWebhook, createdWebhook)

			createdWebhook, err = testClients.user.GetWebhook(ctx, createdWebhook.ID)
			requireNotNilAndNoProblems(t, createdWebhook, err)
			require.Equal(t, relevantAccountID, createdWebhook.BelongsToAccount)

			inviteReq := &types.AccountInvitationCreationRequestInput{
				Note:    t.Name(),
				ToEmail: gofakeit.Email(),
			}
			invitation, err := testClients.user.InviteUserToAccount(ctx, relevantAccountID, inviteReq)
			require.NoError(t, err)

			require.NoError(t, testClients.user.CancelAccountInvitation(ctx, invitation.ID, invitation.Token, t.Name()))

			sentInvitations, err := testClients.user.GetPendingAccountInvitationsFromUser(ctx, nil)
			requireNotNilAndNoProblems(t, sentInvitations, err)
			assert.Empty(t, sentInvitations.Data)

			_, _, c, _ := createUserAndClientForTest(ctx, t, &types.UserRegistrationInput{
				EmailAddress: inviteReq.ToEmail,
				Username:     fakes.BuildFakeUser().Username,
				Password:     gofakeit.Password(true, true, true, true, false, 64),
			})

			invitations, err := c.GetPendingAccountInvitationsForUser(ctx, nil)
			requireNotNilAndNoProblems(t, invitations, err)
			assert.Empty(t, invitations.Data)
		}
	})
}

func (s *TestSuite) TestAccounts_InviteCanBeRejected() {
	s.runForEachClient("should be possible to invite an already-registered user", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			currentStatus, statusErr := testClients.user.UserStatus(s.ctx)
			requireNotNilAndNoProblems(t, currentStatus, statusErr)
			relevantAccountID := currentStatus.ActiveAccount

			// Create webhook.
			exampleWebhook := fakes.BuildFakeWebhook()
			exampleWebhookInput := converters.ConvertWebhookToWebhookCreationRequestInput(exampleWebhook)
			createdWebhook, err := testClients.user.CreateWebhook(ctx, exampleWebhookInput)
			require.NoError(t, err)

			checkWebhookEquality(t, exampleWebhook, createdWebhook)

			createdWebhook, err = testClients.user.GetWebhook(ctx, createdWebhook.ID)
			requireNotNilAndNoProblems(t, createdWebhook, err)
			require.Equal(t, relevantAccountID, createdWebhook.BelongsToAccount)

			u, _, c, _ := createUserAndClientForTest(ctx, t, nil)

			invitation, err := testClients.user.InviteUserToAccount(ctx, relevantAccountID, &types.AccountInvitationCreationRequestInput{
				Note:    t.Name(),
				ToEmail: u.EmailAddress,
			})
			require.NoError(t, err)

			sentInvitations, err := testClients.user.GetPendingAccountInvitationsFromUser(ctx, nil)
			requireNotNilAndNoProblems(t, sentInvitations, err)
			assert.NotEmpty(t, sentInvitations.Data)

			invitations, err := c.GetPendingAccountInvitationsForUser(ctx, nil)
			requireNotNilAndNoProblems(t, invitations, err)
			assert.NotEmpty(t, invitations.Data)

			err = c.RejectAccountInvitation(ctx, invitation.ID, invitation.Token, t.Name())
			require.NoError(t, err)

			sentInvitations, err = testClients.user.GetPendingAccountInvitationsFromUser(ctx, nil)
			requireNotNilAndNoProblems(t, sentInvitations, err)
			assert.Empty(t, sentInvitations.Data)
		}
	})
}

func (s *TestSuite) TestAccounts_ChangingMemberships() {
	s.runForCookieClient("should be possible to change members of a account", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			const userCount = 1

			currentStatus, statusErr := testClients.user.UserStatus(s.ctx)
			requireNotNilAndNoProblems(t, currentStatus, statusErr)

			// fetch account data
			accountCreationInput := &types.AccountCreationRequestInput{
				Name: fakes.BuildFakeAccount().Name,
			}
			account, accountCreationErr := testClients.user.CreateAccount(ctx, accountCreationInput)
			require.NoError(t, accountCreationErr)
			require.NotNil(t, account)

			require.NoError(t, testClients.user.SwitchActiveAccount(ctx, account.ID))

			// Create webhook.
			exampleWebhook := fakes.BuildFakeWebhook()
			exampleWebhookInput := converters.ConvertWebhookToWebhookCreationRequestInput(exampleWebhook)
			createdWebhook, err := testClients.user.CreateWebhook(ctx, exampleWebhookInput)
			require.NoError(t, err)

			checkWebhookEquality(t, exampleWebhook, createdWebhook)

			createdWebhook, err = testClients.user.GetWebhook(ctx, createdWebhook.ID)
			requireNotNilAndNoProblems(t, createdWebhook, err)
			require.Equal(t, account.ID, createdWebhook.BelongsToAccount)

			// create dummy users
			users := []*types.User{}
			clients := []*apiclient.Client{}

			// create users
			for i := 0; i < userCount; i++ {
				u, _, c, _ := createUserAndClientForTest(ctx, t, nil)
				users = append(users, u)
				clients = append(clients, c)

				currentStatus, statusErr = c.UserStatus(s.ctx)
				requireNotNilAndNoProblems(t, currentStatus, statusErr)
			}

			// check that each user cannot see the unreachable webhook
			for i := 0; i < userCount; i++ {
				webhook, err := clients[i].GetWebhook(ctx, createdWebhook.ID)
				require.Nil(t, webhook)
				require.Error(t, err)
			}

			// add them to the account
			for i := 0; i < userCount; i++ {
				invitation, invitationErr := testClients.user.InviteUserToAccount(ctx, account.ID, &types.AccountInvitationCreationRequestInput{
					ToEmail: users[i].EmailAddress,
					Note:    t.Name(),
				})
				require.NoError(t, invitationErr)
				require.NotEmpty(t, invitation.ID)

				invitations, fetchInvitationsErr := clients[i].GetPendingAccountInvitationsForUser(ctx, nil)
				requireNotNilAndNoProblems(t, invitations, fetchInvitationsErr)
				assert.NotEmpty(t, invitations.Data)

				err = clients[i].AcceptAccountInvitation(ctx, invitation.ID, invitation.Token, t.Name())
				require.NoError(t, err)

				require.NoError(t, clients[i].SwitchActiveAccount(ctx, account.ID))

				currentStatus, statusErr = clients[i].UserStatus(s.ctx)
				requireNotNilAndNoProblems(t, currentStatus, statusErr)
				require.Equal(t, currentStatus.ActiveAccount, account.ID)
			}

			// grant all permissions
			for i := 0; i < userCount; i++ {
				input := &types.ModifyUserPermissionsInput{
					Reason:  t.Name(),
					NewRole: authorization.AccountAdminRole.String(),
				}
				require.NoError(t, testClients.user.ModifyMemberPermissions(ctx, account.ID, users[i].ID, input))
			}

			// check that each user can see the webhook
			for i := 0; i < userCount; i++ {
				webhook, webhookRetrievalError := clients[i].GetWebhook(ctx, createdWebhook.ID)
				requireNotNilAndNoProblems(t, webhook, webhookRetrievalError)
			}

			// remove users from account
			for i := 0; i < userCount; i++ {
				require.NoError(t, testClients.user.RemoveUserFromAccount(ctx, account.ID, users[i].ID))
			}

			// check that each user cannot see the webhook
			for i := 0; i < userCount; i++ {
				webhook, webhookRetrievalError := clients[i].GetWebhook(ctx, createdWebhook.ID)
				require.Nil(t, webhook)
				require.Error(t, webhookRetrievalError)
			}

			// Clean up.
			require.NoError(t, testClients.user.ArchiveWebhook(ctx, createdWebhook.ID))

			for i := 0; i < userCount; i++ {
				require.NoError(t, testClients.admin.ArchiveUser(ctx, users[i].ID))
			}
		}
	})
}

func (s *TestSuite) TestAccounts_OwnershipTransfer() {
	s.runForCookieClient("should be possible to transfer ownership of a account", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// create users
			futureOwner, _, futureOwnerClient, _ := createUserAndClientForTest(ctx, t, nil)

			// fetch account data
			accountCreationInput := &types.AccountCreationRequestInput{
				Name: fakes.BuildFakeAccount().Name,
			}
			account, accountCreationErr := testClients.user.CreateAccount(ctx, accountCreationInput)
			require.NoError(t, accountCreationErr)
			require.NotNil(t, account)

			require.NoError(t, testClients.user.SwitchActiveAccount(ctx, account.ID))

			// create a webhook

			// Create webhook.
			exampleWebhook := fakes.BuildFakeWebhook()
			exampleWebhookInput := converters.ConvertWebhookToWebhookCreationRequestInput(exampleWebhook)
			createdWebhook, err := testClients.user.CreateWebhook(ctx, exampleWebhookInput)
			require.NoError(t, err)

			checkWebhookEquality(t, exampleWebhook, createdWebhook)

			createdWebhook, err = testClients.user.GetWebhook(ctx, createdWebhook.ID)
			requireNotNilAndNoProblems(t, createdWebhook, err)

			require.Equal(t, account.ID, createdWebhook.BelongsToAccount)

			// check that user cannot see the webhook
			webhook, err := futureOwnerClient.GetWebhook(ctx, createdWebhook.ID)
			require.Nil(t, webhook)
			require.Error(t, err)

			// add them to the account
			require.NoError(t, testClients.user.TransferAccountOwnership(ctx, account.ID, &types.AccountOwnershipTransferInput{
				Reason:       t.Name(),
				CurrentOwner: account.BelongsToUser,
				NewOwner:     futureOwner.ID,
			}))

			require.NoError(t, futureOwnerClient.SwitchActiveAccount(ctx, account.ID))

			// check that user can see the webhook
			webhook, err = futureOwnerClient.GetWebhook(ctx, createdWebhook.ID)
			requireNotNilAndNoProblems(t, webhook, err)

			// check that old user cannot see the webhook
			webhook, err = testClients.user.GetWebhook(ctx, createdWebhook.ID)
			require.Nil(t, webhook)
			require.Error(t, err)

			// check that new owner can delete the webhook
			require.NoError(t, futureOwnerClient.ArchiveWebhook(ctx, createdWebhook.ID))

			// Clean up.
			require.Error(t, testClients.user.ArchiveWebhook(ctx, createdWebhook.ID))
			require.NoError(t, testClients.admin.ArchiveUser(ctx, futureOwner.ID))
		}
	})
}

func (s *TestSuite) TestAccounts_UsersHaveBackupAccountCreatedForThemWhenRemovedFromLastAccount() {
	s.runForEachClient("should be possible to invite a user via referral link", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			currentStatus, statusErr := testClients.user.UserStatus(s.ctx)
			requireNotNilAndNoProblems(t, currentStatus, statusErr)
			relevantAccountID := currentStatus.ActiveAccount

			inviteReq := &types.AccountInvitationCreationRequestInput{
				Note:    t.Name(),
				ToEmail: gofakeit.Email(),
			}
			createdInvitation, err := testClients.user.InviteUserToAccount(ctx, relevantAccountID, inviteReq)
			require.NoError(t, err)

			createdInvitation, err = testClients.user.GetAccountInvitation(ctx, relevantAccountID, createdInvitation.ID)
			requireNotNilAndNoProblems(t, createdInvitation, err)

			sentInvitations, err := testClients.user.GetPendingAccountInvitationsFromUser(ctx, nil)
			requireNotNilAndNoProblems(t, sentInvitations, err)
			assert.NotEmpty(t, sentInvitations.Data)

			regInput := &types.UserRegistrationInput{
				EmailAddress:    inviteReq.ToEmail,
				Username:        fakes.BuildFakeUser().Username,
				Password:        gofakeit.Password(true, true, true, true, false, 64),
				InvitationID:    createdInvitation.ID,
				InvitationToken: createdInvitation.Token,
			}
			u, _, c, _ := createUserAndClientForTest(ctx, t, regInput)

			accounts, err := c.GetAccounts(ctx, nil)
			require.NoError(t, err)

			assert.Len(t, accounts.Data, 2)

			var (
				found          bool
				otherAccountID string
			)

			for _, account := range accounts.Data {
				if account.ID == relevantAccountID {
					if !found {
						found = true
					}
				} else {
					otherAccountID = account.ID
				}
			}

			require.NotEmpty(t, otherAccountID)
			require.True(t, found)

			require.NoError(t, testClients.user.RemoveUserFromAccount(ctx, relevantAccountID, u.ID))

			u.HashedPassword = regInput.Password

			newCookie, err := testutils.GetLoginCookie(ctx, urlToUse, u)
			require.NoError(t, err)

			require.NoError(t, c.SetOptions(apiclient.UsingCookie(newCookie)))

			account, err := c.GetCurrentAccount(ctx)
			requireNotNilAndNoProblems(t, account, err)
			assert.NotEqual(t, relevantAccountID, account.ID)

			require.True(t, found)
		}
	})
}
