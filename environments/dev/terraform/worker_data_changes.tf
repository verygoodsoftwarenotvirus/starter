resource "google_pubsub_topic" "data_changes_topic" {
  name = "data_changes"
}

resource "google_project_iam_custom_role" "data_changes_worker_role" {
  role_id     = "data_changes_worker_role"
  title       = "Data changes worker role"
  description = "An IAM role for the data changes worker"
  permissions = [
    "secretmanager.versions.access",
    "cloudsql.instances.connect",
    "cloudsql.instances.get",
    "pubsub.topics.list",
    "pubsub.topics.publish",
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

resource "google_storage_bucket" "data_changes_bucket" {
  name     = "data-changes-cloud-function"
  location = "US"
}

data "archive_file" "data_changes_function" {
  type        = "zip"
  source_dir  = "${path.module}/data_changes_cloud_function"
  output_path = "${path.module}/data_changes_cloud_function.zip"
}

resource "google_storage_bucket_object" "data_changes_archive" {
  name   = format("data_changes_function-%s.zip", data.archive_file.data_changes_function.output_md5)
  bucket = google_storage_bucket.data_changes_bucket.name
  source = "${path.module}/data_changes_cloud_function.zip"
}

resource "google_service_account" "data_changes_user_service_account" {
  account_id   = "data-changes-worker"
  display_name = "Data Changes Worker"
}

# Permissions on the service account used by the function and Eventarc trigger
resource "google_project_iam_member" "data_changes_worker" {
  project = local.project_id
  role    = "roles/run.invoker"
  member  = "serviceAccount:${google_service_account.data_changes_user_service_account.email}"
}

resource "google_project_iam_member" "data_changes_user" {
  project = local.project_id
  role    = google_project_iam_custom_role.data_changes_worker_role.id
  member  = format("serviceAccount:%s", google_service_account.data_changes_user_service_account.email)
}

resource "google_cloudfunctions2_function" "data_changes" {
  name        = "data-changes"
  location    = local.gcp_region
  description = format("Data Changes (%s)", data.archive_file.data_changes_function.output_md5)

  build_config {
    runtime     = local.go_runtime
    entry_point = "ProcessDataChange"

    source {
      storage_source {
        bucket = google_storage_bucket.data_changes_bucket.name
        object = google_storage_bucket_object.data_changes_archive.name
      }
    }
  }

  service_config {
    max_instance_count             = 1
    available_memory               = "128Mi"
    ingress_settings               = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision = true
    service_account_email          = google_service_account.data_changes_user_service_account.email

    environment_variables = {
      GOOGLE_CLOUD_SECRET_STORE_PREFIX      = format("projects/%d/secrets", data.google_project.project.number)
      GOOGLE_CLOUD_PROJECT_ID               = data.google_project.project.project_id
      OUTBOUND_EMAILS_TOPIC_NAME            = google_pubsub_topic.outbound_emails_topic.name
      SEARCH_INDEXING_TOPIC_NAME            = google_pubsub_topic.search_index_requests_topic.name
      WEBHOOK_EXECUTION_REQUESTS_TOPIC_NAME = google_pubsub_topic.webhook_execution_requests_topic.name
      COMPANY_NAME_DATABASE_USER            = google_sql_user.api_user.name,
      COMPANY_NAME_DATABASE_NAME            = local.database_name,
      // NOTE: if you're creating a cloud function or server for the first time, terraform cannot configure the database connection.
      // You have to go into the Cloud Run interface and deploy a new revision with a database connection, which will persist upon further deployments.
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
      key        = "COMPANY_NAME_SENDGRID_API_TOKEN"
      project_id = local.project_id
      secret     = google_secret_manager_secret.sendgrid_api_token.secret_id
      version    = "latest"
    }

    secret_environment_variables {
      key        = "COMPANY_NAME_SEGMENT_API_TOKEN"
      project_id = local.project_id
      secret     = google_secret_manager_secret.segment_api_token.secret_id
      version    = "latest"
    }

    secret_environment_variables {
      key        = "COMPANY_NAME_POSTHOG_API_KEY"
      project_id = local.project_id
      secret     = google_secret_manager_secret.posthog_api_key.secret_id
      version    = "latest"
    }
  }

  event_trigger {
    trigger_region        = local.gcp_region
    event_type            = local.pubsub_topic_publish_event
    pubsub_topic          = google_pubsub_topic.data_changes_topic.id
    retry_policy          = "RETRY_POLICY_RETRY"
    service_account_email = google_service_account.data_changes_user_service_account.email
  }
}
