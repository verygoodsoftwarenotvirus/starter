package http

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/panicking"
	"github.com/verygoodsoftwarenotvirus/starter/internal/routing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/net/http2"
)

const (
	serverNamespace = "service"
	loggerName      = "api_server"
)

type (
	Server interface {
		Serve()
		Shutdown(context.Context) error
		Router() routing.Router
	}

	// server is our API http server.
	server struct {
		authService                         types.AuthService
		accountsService                     types.AccountDataService
		accountInvitationsService           types.AccountInvitationDataService
		usersService                        types.UserDataService
		adminService                        types.AdminService
		webhooksService                     types.WebhookDataService
		serviceSettingsService              types.ServiceSettingDataService
		serviceSettingConfigurationsService types.ServiceSettingConfigurationDataService
		oauth2ClientsService                types.OAuth2ClientDataService
		userNotificationsService            types.UserNotificationDataService
		auditLogEntriesService              types.AuditLogEntryDataService
		encoder                             encoding.ServerEncoderDecoder
		logger                              logging.Logger
		router                              routing.Router
		tracer                              tracing.Tracer
		panicker                            panicking.Panicker
		httpServer                          *http.Server
		dataManager                         database.DataManager
		tracerProvider                      tracing.TracerProvider
		config                              Config
	}
)

// ProvideHTTPServer builds a new server instance.
func ProvideHTTPServer(
	ctx context.Context,
	serverSettings Config,
	dataManager database.DataManager,
	logger logging.Logger,
	encoder encoding.ServerEncoderDecoder,
	router routing.Router,
	tracerProvider tracing.TracerProvider,
	authService types.AuthService,
	usersService types.UserDataService,
	accountsService types.AccountDataService,
	accountInvitationsService types.AccountInvitationDataService,
	webhooksService types.WebhookDataService,
	adminService types.AdminService,
	serviceSettingDataService types.ServiceSettingDataService,
	serviceSettingConfigurationsService types.ServiceSettingConfigurationDataService,
	oauth2ClientDataService types.OAuth2ClientDataService,
	userNotificationsService types.UserNotificationDataService,
	auditLogService types.AuditLogEntryDataService,
) (Server, error) {
	srv := &server{
		config: serverSettings,

		// infra things,
		tracer:         tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(loggerName)),
		encoder:        encoder,
		logger:         logging.EnsureLogger(logger).WithName(loggerName),
		panicker:       panicking.NewProductionPanicker(),
		httpServer:     provideStdLibHTTPServer(serverSettings.HTTPPort),
		dataManager:    dataManager,
		tracerProvider: tracerProvider,

		// services,
		adminService:                        adminService,
		auditLogEntriesService:              auditLogService,
		authService:                         authService,
		accountsService:                     accountsService,
		accountInvitationsService:           accountInvitationsService,
		serviceSettingsService:              serviceSettingDataService,
		serviceSettingConfigurationsService: serviceSettingConfigurationsService,
		usersService:                        usersService,
		userNotificationsService:            userNotificationsService,
		webhooksService:                     webhooksService,
		oauth2ClientsService:                oauth2ClientDataService,
	}

	srv.setupRouter(ctx, router)
	logger.Debug("HTTP server successfully constructed")

	return srv, nil
}

// Router returns the router.
func (s *server) Router() routing.Router {
	return s.router
}

// Shutdown shuts down the server.
func (s *server) Shutdown(ctx context.Context) error {
	s.dataManager.Close()

	if err := s.tracerProvider.ForceFlush(ctx); err != nil {
		s.logger.Error(err, "flushing traces")
	}

	return s.httpServer.Shutdown(ctx)
}

// Serve serves HTTP traffic.
func (s *server) Serve() {
	s.logger.Debug("setting up server")

	s.httpServer.Handler = otelhttp.NewHandler(
		s.router.Handler(),
		serverNamespace,
		otelhttp.WithSpanNameFormatter(tracing.FormatSpan),
	)

	http2ServerConf := &http2.Server{}
	if err := http2.ConfigureServer(s.httpServer, http2ServerConf); err != nil {
		s.logger.Error(err, "configuring HTTP2")
		s.panicker.Panic(err)
	}

	s.logger.WithValue("listening_on", s.httpServer.Addr).Info("Listening for HTTP requests")

	if s.config.HTTPSCertificateFile != "" && s.config.HTTPSCertificateKeyFile != "" {
		// returns ErrServerClosed on graceful close.
		if err := s.httpServer.ListenAndServeTLS(s.config.HTTPSCertificateFile, s.config.HTTPSCertificateKeyFile); err != nil {
			if errors.Is(err, http.ErrServerClosed) {
				// NOTE: there is a chance that next line won't have time to run,
				// as main() doesn't wait for this goroutine to stop.
				os.Exit(0)
			}

			s.logger.Error(err, "shutting server down")
		}
	} else {
		// returns ErrServerClosed on graceful close.
		if err := s.httpServer.ListenAndServe(); err != nil {
			if errors.Is(err, http.ErrServerClosed) {
				// NOTE: there is a chance that next line won't have time to run,
				// as main() doesn't wait for this goroutine to stop.
				os.Exit(0)
			}

			s.logger.Error(err, "shutting server down")
		}
	}
}

const (
	maxTimeout   = 120 * time.Second
	readTimeout  = 5 * time.Second
	writeTimeout = 2 * readTimeout
	idleTimeout  = maxTimeout
)

// provideStdLibHTTPServer provides an HTTP httpServer.
func provideStdLibHTTPServer(port uint16) *http.Server {
	// heavily inspired by https://blog.cloudflare.com/exposing-go-on-the-internet/
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
		TLSConfig: &tls.Config{
			// "Only use curves which have assembly implementations"
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
	}

	return srv
}
