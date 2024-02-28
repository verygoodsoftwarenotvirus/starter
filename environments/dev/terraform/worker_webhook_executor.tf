resource "google_pubsub_topic" "webhook_execution_requests_topic" {
  name = "webhook_execution_requests"
}

resource "google_project_iam_custom_role" "webhook_executor_role" {
  role_id     = "webhook_executor_role"
  title       = "Webhook executor role"
  description = "An IAM role for the webhook executor"
  permissions = [
    "secretmanager.versions.access",
    "cloudsql.instances.connect",
    "cloudsql.instances.get",
    "pubsub.topics.list",
    "pubsub.subscriptions.consume",
    "pubsub.subscriptions.create",
    "pubsub.subscriptions.delete",
    "eventarc.events.receiveAuditLogWritten",
    "eventarc.events.receiveEvent",
    "run.jobs.run",
    "run.routes.invoke",
    "artifactregistry.dockerimages.get",
    "artifactregistry.dockerimages.list",
  ]
}

resource "google_storage_bucket" "webhook_executor_bucket" {
  name     = "webhook-executor-cloud-function"
  location = "US"
}

data "archive_file" "webhook_executor_function" {
  type        = "zip"
  source_dir  = "${path.module}/webhook_executor_cloud_function"
  output_path = "${path.module}/webhook_executor_cloud_function.zip"
}

resource "google_storage_bucket_object" "webhook_executor_archive" {
  name   = format("webhook_executor_function-%s.zip", data.archive_file.webhook_executor_function.output_md5)
  bucket = google_storage_bucket.webhook_executor_bucket.name
  source = "${path.module}/webhook_executor_cloud_function.zip"
}

resource "google_service_account" "webhook_executor_user_service_account" {
  account_id   = "webhook-executor-worker"
  display_name = "Webhook Executor Worker"
}

resource "google_project_iam_member" "webhook_executor_user" {
  project = local.project_id
  role    = google_project_iam_custom_role.webhook_executor_role.id
  member  = format("serviceAccount:%s", google_service_account.webhook_executor_user_service_account.email)
}

resource "google_cloudfunctions2_function" "webhook_executor" {
  name        = "webhook-executor"
  location    = local.gcp_region
  description = format("Webhook Executor (%s)", data.archive_file.webhook_executor_function.output_md5)

  build_config {
    runtime     = local.go_runtime
    entry_point = "ExecuteWebhook"

    source {
      storage_source {
        bucket = google_storage_bucket.webhook_executor_bucket.name
        object = google_storage_bucket_object.webhook_executor_archive.name
      }
    }
  }

  service_config {
    max_instance_count             = 1
    available_memory               = "128Mi"
    ingress_settings               = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision = true
    service_account_email          = google_service_account.webhook_executor_user_service_account.email

    environment_variables = {
      COMPANY_NAME_SERVICE_ENVIRONMENT               = local.environment,
      COMPANY_NAME_DATABASE_USER                     = google_sql_user.api_user.name,
      COMPANY_NAME_DATABASE_NAME                     = local.database_name,
      COMPANY_NAME_DATABASE_INSTANCE_CONNECTION_NAME = google_sql_database_instance.dev.connection_name,
      GOOGLE_CLOUD_SECRET_STORE_PREFIX               = format("projects/%d/secrets", data.google_project.project.number)
      GOOGLE_CLOUD_PROJECT_ID                        = data.google_project.project.project_id
    }

    secret_environment_variables {
      key        = "COMPANY_NAME_DATABASE_PASSWORD"
      project_id = local.project_id
      secret     = google_secret_manager_secret.api_user_database_password.secret_id
      version    = "latest"
    }

    secret_environment_variables {
      key        = "COMPANY_NAME_OAUTH2_TOKEN_ENCRYPTION_KEY"
      project_id = local.project_id
      secret     = google_secret_manager_secret.oauth2_token_encryption_key.secret_id
      version    = "latest"
    }
  }

  event_trigger {
    trigger_region        = local.gcp_region
    event_type            = local.pubsub_topic_publish_event
    pubsub_topic          = google_pubsub_topic.webhook_execution_requests_topic.id
    retry_policy          = "RETRY_POLICY_RETRY"
    service_account_email = google_service_account.webhook_executor_user_service_account.email
  }
}
