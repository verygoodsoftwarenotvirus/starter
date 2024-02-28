resource "google_pubsub_topic" "search_index_requests_topic" {
  name = "search_index_requests"
}

resource "google_project_iam_custom_role" "search_indexer_role" {
  role_id     = "search_indexer_role"
  title       = "Search indexer role"
  description = "An IAM role for the search indexer"
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

resource "google_storage_bucket" "search_indexer_bucket" {
  name     = "search-indexer-cloud-function"
  location = "US"
}

data "archive_file" "search_indexer_function" {
  type        = "zip"
  source_dir  = "${path.module}/search_indexer_cloud_function"
  output_path = "${path.module}/search_indexer_cloud_function.zip"
}

resource "google_storage_bucket_object" "search_indexer_archive" {
  name   = format("search_indexer_function-%s.zip", data.archive_file.search_indexer_function.output_md5)
  bucket = google_storage_bucket.search_indexer_bucket.name
  source = "${path.module}/search_indexer_cloud_function.zip"
}

resource "google_service_account" "search_indexer_user_service_account" {
  account_id   = "search-indexer-worker"
  display_name = "Search Indexer Worker"
}

resource "google_project_iam_member" "search_indexer_user" {
  project = local.project_id
  role    = google_project_iam_custom_role.search_indexer_role.id
  member  = format("serviceAccount:%s", google_service_account.search_indexer_user_service_account.email)
}

resource "google_cloudfunctions2_function" "search_indexer" {
  depends_on = [
    google_secret_manager_secret.algolia_api_key,
    google_secret_manager_secret.algolia_application_id,
  ]

  name        = "search-indexer"
  location    = local.gcp_region
  description = format("Search Indexer (%s)", data.archive_file.search_indexer_function.output_md5)

  build_config {
    runtime     = local.go_runtime
    entry_point = "IndexDataForSearch"

    source {
      storage_source {
        bucket = google_storage_bucket.search_indexer_bucket.name
        object = google_storage_bucket_object.search_indexer_archive.name
      }
    }
  }

  service_config {
    max_instance_count             = 1
    available_memory               = "128Mi"
    ingress_settings               = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision = true
    service_account_email          = google_service_account.search_indexer_user_service_account.email

    environment_variables = {
      COMPANY_NAME_SERVICE_ENVIRONMENT = local.environment,
      # TODO: use the search_indexer_user for this, currently it has permission denied for accessing tables
      # https://dba.stackexchange.com/questions/53914/permission-denied-for-relation-table
      # https://www.postgresql.org/docs/13/sql-alterdefaultprivileges.html
      COMPANY_NAME_DATABASE_USER = google_sql_user.api_user.name,
      COMPANY_NAME_DATABASE_NAME = local.database_name,
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
      key        = "COMPANY_NAME_ALGOLIA_API_KEY"
      project_id = local.project_id
      secret     = google_secret_manager_secret.algolia_api_key.secret_id
      version    = "latest"
    }

    secret_environment_variables {
      key        = "COMPANY_NAME_ALGOLIA_APPLICATION_ID"
      project_id = local.project_id
      secret     = google_secret_manager_secret.algolia_application_id.secret_id
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
    pubsub_topic          = google_pubsub_topic.search_index_requests_topic.id
    retry_policy          = "RETRY_POLICY_RETRY"
    service_account_email = google_service_account.search_indexer_user_service_account.email
  }
}
