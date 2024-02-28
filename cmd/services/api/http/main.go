package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/server/http/build"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	_ "github.com/KimMachineGun/automemlimit"
	_ "go.uber.org/automaxprocs"
)

const (
	configFilepathEnvVar       = "CONFIGURATION_FILEPATH"
	googleCloudIndicatorEnvVar = "RUNNING_IN_GCP"
)

func getConfig(ctx context.Context) (*config.InstanceConfig, error) {
	var cfg *config.InstanceConfig
	if os.Getenv(googleCloudIndicatorEnvVar) != "" {
		client, err := secretmanager.NewClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("instantiating secret manager: %w", err)
		}

		c, err := config.GetAPIServerConfigFromGoogleCloudRunEnvironment(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("fetching config from GCP: %w", err)
		}

		cfg = c
	} else if configFilepath := os.Getenv(configFilepathEnvVar); configFilepath != "" {
		configBytes, err := os.ReadFile(configFilepath)
		if err != nil {
			return nil, fmt.Errorf("reading local config file: %w", err)
		}

		if err = json.NewDecoder(bytes.NewReader(configBytes)).Decode(&cfg); err != nil || cfg == nil {
			return nil, fmt.Errorf("decoding config file contents: %w", err)
		}
	} else {
		return nil, errors.New("no config provided")
	}

	if err := cfg.ValidateWithContext(ctx, true); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

func main() {
	rootCtx := context.Background()

	cfg, err := getConfig(rootCtx)
	if err != nil {
		log.Fatal(err)
	}

	// only allow initialization to take so long.
	buildCtx, cancel := context.WithTimeout(rootCtx, cfg.Server.StartupDeadline)

	// build our server struct.
	srv, err := build.Build(buildCtx, cfg)
	if err != nil {
		log.Fatal(err)
	}

	cancel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(
		signalChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGTERM,
	)

	// Run server
	go srv.Serve()

	// os.Interrupt
	<-signalChan

	go func() {
		// os.Kill
		<-signalChan
	}()

	cancelCtx, cancelShutdown := context.WithTimeout(rootCtx, 10*time.Second)
	defer cancelShutdown()

	// Gracefully shutdown the server by waiting on existing requests (except websockets).
	if err = srv.Shutdown(cancelCtx); err != nil {
		panic(err)
	}
}
