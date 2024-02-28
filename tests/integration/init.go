package integration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	dbconfig "github.com/verygoodsoftwarenotvirus/starter/internal/database/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres"
	"github.com/verygoodsoftwarenotvirus/starter/internal/identifiers"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	logcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"
	"github.com/verygoodsoftwarenotvirus/starter/internal/server/http/utils"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	debug         = true
	nonexistentID = "_NOT_REAL_LOL_"
)

var (
	urlToUse       string
	parsedURLToUse *url.URL
	dbmanager      database.DataManager

	createdClientID, createdClientSecret string

	premadeAdminUser = &types.User{
		ID:              identifiers.New(),
		TwoFactorSecret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		EmailAddress:    "integration_tests@companyname.email",
		Username:        "exampleUser",
		HashedPassword:  "integration-tests-are-cool",
	}
)

func init() {
	ctx, span := tracing.StartSpan(context.Background())
	defer span.End()

	logger := (&logcfg.Config{Provider: logcfg.ProviderSlog}).ProvideLogger()

	parsedURLToUse = serverutils.DetermineServiceURL()
	urlToUse = parsedURLToUse.String()

	logger.WithValue(keys.URLKey, urlToUse).Info("checking server")
	serverutils.EnsureServerIsUp(ctx, urlToUse)

	dbAddr := os.Getenv("TARGET_DATABASE")
	if dbAddr == "" {
		panic("empty database address provided")
	}

	cfg := &dbconfig.Config{
		OAuth2TokenEncryptionKey: "                                ",
		ConnectionDetails:        dbAddr,
		Debug:                    false,
		RunMigrations:            false,
		MaxPingAttempts:          500,
	}

	var err error
	dbmanager, err = postgres.ProvideDatabaseClient(ctx, logger, tracing.NewNoopTracerProvider(), cfg)
	if err != nil {
		panic(err)
	}

	hasher := authentication.ProvideArgon2Authenticator(logger, tracing.NewNoopTracerProvider())
	actuallyHashedPass, err := hasher.HashPassword(ctx, premadeAdminUser.HashedPassword)
	if err != nil {
		panic(err)
	}

	if _, err = dbmanager.GetUserByUsername(ctx, premadeAdminUser.Username); err != nil {
		_, creationErr := dbmanager.CreateUser(ctx, &types.UserDatabaseCreationInput{
			ID:              premadeAdminUser.ID,
			Username:        premadeAdminUser.Username,
			EmailAddress:    premadeAdminUser.EmailAddress,
			HashedPassword:  actuallyHashedPass,
			TwoFactorSecret: premadeAdminUser.TwoFactorSecret,
		})
		if creationErr != nil {
			panic(creationErr)
		}
	}

	if err = dbmanager.MarkUserTwoFactorSecretAsVerified(ctx, premadeAdminUser.ID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		panic(err)
	}

	clientID, err := random.GenerateHexEncodedString(ctx, 16)
	if err != nil {
		panic(err)
	}

	clientSecret, err := random.GenerateHexEncodedString(ctx, 16)
	if err != nil {
		panic(err)
	}

	createdClient, err := dbmanager.CreateOAuth2Client(ctx, &types.OAuth2ClientDatabaseCreationInput{
		ID:           identifiers.New(),
		Name:         "integration_client",
		Description:  "integration test client",
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if err != nil {
		panic(err)
	}

	createdClientID, createdClientSecret = createdClient.ClientID, createdClient.ClientSecret

	db, err := sql.Open("pgx", dbAddr)
	if err != nil {
		panic(err)
	}

	if _, err = db.Exec(`UPDATE users SET service_role = $1 WHERE id = $2`, authorization.ServiceAdminRole.String(), premadeAdminUser.ID); err != nil {
		panic(err)
	}

	fiftySpaces := strings.Repeat("\n", 50)
	fmt.Printf("%s\tRunning tests%s", fiftySpaces, fiftySpaces)
}
