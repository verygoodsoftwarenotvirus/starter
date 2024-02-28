package config

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	dbconfig "github.com/verygoodsoftwarenotvirus/starter/internal/database/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/server/http"
	authservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/authentication"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerConfig_EncodeToFile(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		cfg := &InstanceConfig{
			Server: http.Config{
				HTTPPort:        1234,
				Debug:           false,
				StartupDeadline: time.Minute,
			},
			Meta: MetaSettings{
				RunMode: DevelopmentRunMode,
			},
			Encoding: encoding.Config{
				ContentType: "application/json",
			},
			Observability: observability.Config{},
			Services: ServicesConfig{
				Auth: authservice.Config{
					Cookies: authservice.CookieConfig{
						Name:     "service_name_api_cookie",
						Domain:   "https://verygoodsoftwarenotvirus.ru",
						Lifetime: time.Second,
					},
					MinimumUsernameLength: 4,
					MinimumPasswordLength: 8,
					EnableUserSignup:      true,
				},
			},
			Database: dbconfig.Config{
				Debug:             true,
				RunMigrations:     true,
				ConnectionDetails: "postgres://username:password@host/table",
			},
		}

		f, err := os.CreateTemp("", "")
		require.NoError(t, err)

		assert.NoError(t, cfg.EncodeToFile(f.Name(), json.Marshal))
	})

	T.Run("with error marshaling", func(t *testing.T) {
		t.Parallel()

		cfg := &InstanceConfig{}

		f, err := os.CreateTemp("", "")
		require.NoError(t, err)

		assert.Error(t, cfg.EncodeToFile(f.Name(), func(any) ([]byte, error) {
			return nil, errors.New("blah")
		}))
	})
}
