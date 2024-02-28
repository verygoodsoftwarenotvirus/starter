package chi

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/routing"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	servertiming "github.com/mitchellh/go-server-timing"
)

const (
	maxTimeout = 120 * time.Second
	maxCORSAge = 300
)

var (
	errInvalidMethod = errors.New("invalid method")
)

var _ routing.Router = (*router)(nil)

type router struct {
	router chi.Router
	cfg    *routing.Config
	tracer tracing.Tracer
	logger logging.Logger
}

var (
	validDomains = map[string]struct{}{
		"www.whatever.dev":   {},
		"admin.whatever.dev": {},
	}
)

func buildChiMux(logger logging.Logger, tracer tracing.Tracer, cfg *routing.Config) chi.Router {
	corsHandler := cors.New(cors.Options{
		AllowOriginFunc: func(r *http.Request, origin string) bool {
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}
			_, ok := validDomains[u.Hostname()]

			return ok || cfg.EnableCORSForLocalhost && u.Hostname() == "localhost"
		},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPatch,
			http.MethodPut,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"Set-Cookie"},
		AllowCredentials: true,
		MaxAge:           maxCORSAge,
	})

	mux := chi.NewRouter()
	mux.Use(
		buildTracingMiddleware(tracer),
		chimiddleware.RequestID,
		chimiddleware.RealIP,
		chimiddleware.Timeout(maxTimeout),
		buildLoggingMiddleware(logging.EnsureLogger(logger).WithName("router"), tracer, cfg.SilenceRouteLogging),
		corsHandler.Handler,
		func(next http.Handler) http.Handler {
			return servertiming.Middleware(next, nil)
		},
	)

	// all middleware must be defined before routes on a mux.

	return mux
}

func buildRouter(mux chi.Router, l logging.Logger, tracerProvider tracing.TracerProvider, cfg *routing.Config) *router {
	logger := logging.EnsureLogger(l)
	tracer := tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer("router"))

	if mux == nil {
		logger.Debug("starting with a new mux")
		mux = buildChiMux(logger, tracer, cfg)
	}

	r := &router{
		router: mux,
		tracer: tracer,
		logger: logger,
	}

	return r
}

func convertMiddleware(in ...routing.Middleware) []func(handler http.Handler) http.Handler {
	out := []func(handler http.Handler) http.Handler{}

	for _, x := range in {
		if x != nil {
			out = append(out, x)
		}
	}

	return out
}

// NewRouter constructs a new router.
func NewRouter(logger logging.Logger, tracerProvider tracing.TracerProvider, cfg *routing.Config) routing.Router {
	return buildRouter(nil, logger, tracerProvider, cfg)
}

func (r *router) clone() *router {
	return buildRouter(r.router, r.logger, tracing.NewNoopTracerProvider(), r.cfg)
}

// WithMiddleware returns a router with certain middleware applied.
func (r *router) WithMiddleware(middleware ...routing.Middleware) routing.Router {
	x := r.clone()

	x.router = x.router.With(convertMiddleware(middleware...)...)

	return x
}

// LogRoutes logs the described routes.
func (r *router) LogRoutes() {
	routerWalkFunc := func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		r.logger.WithValues(map[string]any{
			"method": method,
			"route":  route,
		}).Info("route found")

		return nil
	}

	if err := chi.Walk(r.router, routerWalkFunc); err != nil {
		r.logger.Error(err, "logging routes")
	}
}

// Route lets you apply a set of routes to a subrouter with a provided pattern.
func (r *router) Route(pattern string, routeFunction func(r routing.Router)) routing.Router {
	r.router.Route(pattern, func(subrouter chi.Router) {
		routeFunction(buildRouter(subrouter, r.logger, tracing.NewNoopTracerProvider(), r.cfg))
	})

	return r
}

// AddRoute adds a route to the router.
func (r *router) AddRoute(method, path string, handler http.HandlerFunc, middleware ...routing.Middleware) error {
	switch strings.TrimSpace(strings.ToUpper(method)) {
	case http.MethodGet:
		r.router.With(convertMiddleware(middleware...)...).Get(path, handler)
	case http.MethodHead:
		r.router.With(convertMiddleware(middleware...)...).Head(path, handler)
	case http.MethodPost:
		r.router.With(convertMiddleware(middleware...)...).Post(path, handler)
	case http.MethodPut:
		r.router.With(convertMiddleware(middleware...)...).Put(path, handler)
	case http.MethodPatch:
		r.router.With(convertMiddleware(middleware...)...).Patch(path, handler)
	case http.MethodDelete:
		r.router.With(convertMiddleware(middleware...)...).Delete(path, handler)
	case http.MethodConnect:
		r.router.With(convertMiddleware(middleware...)...).Connect(path, handler)
	case http.MethodOptions:
		r.router.With(convertMiddleware(middleware...)...).Options(path, handler)
	case http.MethodTrace:
		r.router.With(convertMiddleware(middleware...)...).Trace(path, handler)
	default:
		return fmt.Errorf("%s: %w", method, errInvalidMethod)
	}

	return nil
}

// Handler our interface by wrapping the underlying router's Handler method.
func (r *router) Handler() http.Handler {
	return r.router
}

// Handle our interface by wrapping the underlying router's Handle method.
func (r *router) Handle(pattern string, handler http.Handler) {
	r.router.Handle(pattern, handler)
}

// HandleFunc satisfies our interface by wrapping the underlying router's HandleFunc method.
func (r *router) HandleFunc(pattern string, handler http.HandlerFunc) {
	r.router.HandleFunc(pattern, handler)
}

// Connect satisfies our interface by wrapping the underlying router's Connect method.
func (r *router) Connect(pattern string, handler http.HandlerFunc) {
	r.router.Connect(pattern, handler)
}

// Delete satisfies our interface by wrapping the underlying router's Delete method.
func (r *router) Delete(pattern string, handler http.HandlerFunc) {
	r.router.Delete(pattern, handler)
}

// Get satisfies our interface by wrapping the underlying router's Get method.
func (r *router) Get(pattern string, handler http.HandlerFunc) {
	r.router.Get(pattern, handler)
}

// Head satisfies our interface by wrapping the underlying router's Head method.
func (r *router) Head(pattern string, handler http.HandlerFunc) {
	r.router.Head(pattern, handler)
}

// Options satisfies our interface by wrapping the underlying router's Options method.
func (r *router) Options(pattern string, handler http.HandlerFunc) {
	r.router.Options(pattern, handler)
}

// Patch satisfies our interface by wrapping the underlying router's Patch method.
func (r *router) Patch(pattern string, handler http.HandlerFunc) {
	r.router.Patch(pattern, handler)
}

// Post satisfies our interface by wrapping the underlying router's Post method.
func (r *router) Post(pattern string, handler http.HandlerFunc) {
	r.router.Post(pattern, handler)
}

// Put satisfies our interface by wrapping the underlying router's Put method.
func (r *router) Put(pattern string, handler http.HandlerFunc) {
	r.router.Put(pattern, handler)
}

// Trace satisfies our interface by wrapping the underlying router's Trace method.
func (r *router) Trace(pattern string, handler http.HandlerFunc) {
	r.router.Trace(pattern, handler)
}

// BuildRouteParamIDFetcher builds a function that fetches a given key from a path with variables added by a router.
func (r *router) BuildRouteParamIDFetcher(logger logging.Logger, key, logDescription string) func(req *http.Request) uint64 {
	return func(req *http.Request) uint64 {
		v := chi.URLParam(req, key)
		u, err := strconv.ParseUint(v, 10, 64)
		// this should never happen
		if err != nil && logDescription != "" {
			logger.Error(err, fmt.Sprintf("fetching %s ID from request", logDescription))
		}

		return u
	}
}

// BuildRouteParamStringIDFetcher builds a function that fetches a given key from a path with variables added by a router.
func (r *router) BuildRouteParamStringIDFetcher(key string) func(req *http.Request) string {
	return func(req *http.Request) string {
		return chi.URLParam(req, key)
	}
}
