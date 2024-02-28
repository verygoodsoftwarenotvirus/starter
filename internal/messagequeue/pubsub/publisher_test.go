package pubsub

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"

	"cloud.google.com/go/pubsub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/gcloud"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func buildPubSubBackedPublisher(t *testing.T, ctx context.Context) (publisher messagequeue.Publisher, shutdownFunc func(context.Context) error) {
	t.Helper()

	projectID, err := random.GenerateHexEncodedString(ctx, 8)
	require.NoError(t, err)
	topicID, err := random.GenerateHexEncodedString(ctx, 8)
	require.NoError(t, err)

	pubsubContainer, err := gcloud.RunPubsubContainer(
		ctx,
		testcontainers.WithImage("google/cloud-sdk:latest"),
		gcloud.WithProjectID(projectID),
	)
	if err != nil {
		panic(err)
	}

	conn, err := grpc.Dial(pubsubContainer.URI, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	require.NotNil(t, conn)

	client, err := pubsub.NewClient(ctx, projectID, option.WithGRPCConn(conn))
	require.NoError(t, err)

	logger := logging.NewNoopLogger()
	provider := ProvidePubSubPublisherProvider(logger, tracing.NewNoopTracerProvider(), client)
	require.NotNil(t, provider)

	publisher, err = provider.ProvidePublisher(topicID)
	assert.NotNil(t, publisher)
	assert.NoError(t, err)

	return publisher, pubsubContainer.Terminate
}

func Test_pubSubPublisher_Publish(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		publisher, shutdownFunc := buildPubSubBackedPublisher(t, ctx)
		defer func() {
			require.NoError(t, shutdownFunc(ctx))
		}()

		inputData := &struct {
			Name string `json:"name"`
		}{
			Name: t.Name(),
		}

		assert.NoError(t, publisher.Publish(ctx, inputData))
	})
}
