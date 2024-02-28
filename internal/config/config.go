package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"

	analyticsconfig "github.com/verygoodsoftwarenotvirus/starter/internal/analytics/config"
	dbconfig "github.com/verygoodsoftwarenotvirus/starter/internal/database/config"
	emailconfig "github.com/verygoodsoftwarenotvirus/starter/internal/email/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	featureflagsconfig "github.com/verygoodsoftwarenotvirus/starter/internal/featureflags/config"
	msgconfig "github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/routing"
	searchcfg "github.com/verygoodsoftwarenotvirus/starter/internal/search/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/server/http"

	"github.com/hashicorp/go-multierror"
)

const (
	// DevelopmentRunMode is the run mode for a development environment.
	DevelopmentRunMode runMode = "development"
	// TestingRunMode is the run mode for a testing environment.
	TestingRunMode runMode = "testing"
	// ProductionRunMode is the run mode for a production environment.
	ProductionRunMode runMode = "production"
)

type (
	// runMode describes what method of operation the server is under.
	runMode string

	// CloserFunc calls all io.Closers in the service.
	CloserFunc func()

	// InstanceConfig configures an instance of the service. It is composed of all the other setting structs.
	InstanceConfig struct {
		_             struct{}                  `json:"-"`
		Observability observability.Config      `json:"observability" toml:"observability,omitempty"`
		Email         emailconfig.Config        `json:"email"         toml:"email,omitempty"`
		Analytics     analyticsconfig.Config    `json:"analytics"     toml:"analytics,omitempty"`
		Search        searchcfg.Config          `json:"search"        toml:"search,omitempty"`
		FeatureFlags  featureflagsconfig.Config `json:"featureFlags"  toml:"events,omitempty"`
		Encoding      encoding.Config           `json:"encoding"      toml:"encoding,omitempty"`
		Meta          MetaSettings              `json:"meta"          toml:"meta,omitempty"`
		Routing       routing.Config            `json:"routing"       toml:"routing,omitempty"`
		Events        msgconfig.Config          `json:"events"        toml:"events,omitempty"`
		Server        http.Config               `json:"server"        toml:"server,omitempty"`
		Database      dbconfig.Config           `json:"database"      toml:"database,omitempty"`
		Services      ServicesConfig            `json:"services"      toml:"services,omitempty"`
	}
)

// EncodeToFile renders your config to a file given your favorite encoder.
func (cfg *InstanceConfig) EncodeToFile(path string, marshaller func(v any) ([]byte, error)) error {
	if cfg == nil {
		return errors.New("nil config")
	}

	byteSlice, err := marshaller(*cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, byteSlice, 0o600)
}

// ValidateWithContext validates a InstanceConfig struct.
func (cfg *InstanceConfig) ValidateWithContext(ctx context.Context, validateServices bool) error {
	var result *multierror.Error

	validators := map[string]func(context.Context) error{
		"Routing":       cfg.Routing.ValidateWithContext,
		"Meta":          cfg.Meta.ValidateWithContext,
		"Encoding":      cfg.Encoding.ValidateWithContext,
		"Analytics":     cfg.Analytics.ValidateWithContext,
		"Observability": cfg.Observability.ValidateWithContext,
		"Database":      cfg.Database.ValidateWithContext,
		"server":        cfg.Server.ValidateWithContext,
		"Email":         cfg.Email.ValidateWithContext,
		"FeatureFlags":  cfg.FeatureFlags.ValidateWithContext,
		"Search":        cfg.Search.ValidateWithContext,
	}

	for name, validator := range validators {
		if err := validator(ctx); err != nil {
			result = multierror.Append(fmt.Errorf("error validating %s config: %w", name, err), result)
		}
	}

	if validateServices {
		if err := cfg.Services.ValidateWithContext(ctx); err != nil {
			result = multierror.Append(fmt.Errorf("error validating Services config: %w", err), result)
		}
	}

	return result.ErrorOrNil()
}

func (cfg *InstanceConfig) Commit() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for i := range info.Settings {
			if info.Settings[i].Key == "vcs.revision" {
				return info.Settings[i].Value
			}
		}
	}

	return ""
}
