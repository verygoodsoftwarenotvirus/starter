package authentication

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Validate(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		cfg := &Config{
			Cookies: CookieConfig{
				Name:     "name",
				Domain:   "domain",
				Lifetime: time.Second,
			},
			Debug:                 false,
			EnableUserSignup:      false,
			MinimumUsernameLength: 123,
			MinimumPasswordLength: 123,
		}

		assert.NoError(t, cfg.ValidateWithContext(ctx))
	})
}

func TestCookieConfig_Validate(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		cfg := &CookieConfig{
			Name:     "name",
			Domain:   "domain",
			Lifetime: time.Second,
		}
		ctx := context.Background()

		assert.NoError(t, cfg.ValidateWithContext(ctx))
	})
}
