resource "google_project_iam_custom_role" "search_data_index_scheduler_role" {
  role_id     = "search_data_index_scheduler_role"
  title       = "Search data index scheduler role"
  description = "An IAM role for the Search data index scheduler"
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

resource "google_service_account" "search_data_index_scheduler_user_service_account" {
  account_id   = "search-data-index-scheduler"
  display_name = "Search Data Index Scheduler"
}

resource "google_project_iam_member" "search_data_index_scheduler_user" {
  project = local.project_id
  role    = google_project_iam_custom_role.search_data_index_scheduler_role.id
  member  = format("serviceAccount:%s", google_service_account.search_data_index_scheduler_user_service_account.email)
}

resource "google_cloud_run_v2_job" "search_data_index_scheduler" {
  name     = "search-data-index-scheduler"
  location = local.gcp_region

  template {
    task_count  = 1
    parallelism = 1

    template {
      execution_environment = "EXECUTION_ENVIRONMENT_GEN2"
      max_retries           = 1
      service_account       = google_service_account.search_data_index_scheduler_user_service_account.email

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = [google_sql_database_instance.dev.connection_name]
        }
      }

      containers {
        image = format("%s-docker.pkg.dev/%s/%s/search-data-index-scheduler", local.gcp_region, local.project_id, google_artifact_registry_repository.dev_repository.name)

        resources {
          limits = {
            cpu    = "1"
            memory = "512Mi"
          }
        }

        env {
          name  = "COMPANY_NAME_DATABASE_USER"
          value = google_sql_user.api_user.name
        }

        env {
          name  = "COMPANY_NAME_DATABASE_NAME"
          value = local.database_name
        }

        env {
          name  = "COMPANY_NAME_DATABASE_INSTANCE_CONNECTION_NAME"
          value = google_sql_database_instance.dev.connection_name
        }

        env {
          name  = "GOOGLE_CLOUD_SECRET_STORE_PREFIX"
          value = format("projects/%d/secrets", data.google_project.project.number)
        }

        env {
          name  = "GOOGLE_CLOUD_PROJECT_ID"
          value = data.google_project.project.project_id
        }

        env {
          name  = "DATA_CHANGES_TOPIC_NAME"
          value = google_pubsub_topic.data_changes_topic.name
        }

        env {
          name  = "SEARCH_INDEXING_TOPIC_NAME"
          value = google_pubsub_topic.search_index_requests_topic.name
        }

        env {
          name = "COMPANY_NAME_OAUTH2_TOKEN_ENCRYPTION_KEY"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.oauth2_token_encryption_key.secret_id
              version = "latest"
            }
          }
        }

        env {
          name = "COMPANY_NAME_DATABASE_PASSWORD"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.api_user_database_password.secret_id
              version = "latest"
            }
          }
        }

        volume_mounts {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      launch_stage,
    ]
  }
}

resource "google_cloud_scheduler_job" "run_data_index_scheduler" {
  name             = "scheduled-data-indexing"
  description      = "Runs the search data index scheduler every 30 minutes"
  schedule         = "*/30 * * * *"
  time_zone        = "America/Chicago"
  attempt_deadline = "320s"

  retry_config {
    retry_count = 1
  }


  http_target {
    http_method = "POST"
    uri         = "https://${google_cloud_run_v2_job.search_data_index_scheduler.location}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${data.google_project.project.number}/jobs/${google_cloud_run_v2_job.search_data_index_scheduler.name}:run"

    oauth_token {
      service_account_email = google_service_account.search_data_index_scheduler_user_service_account.email
    }
  }

  # Use an explicit depends_on clause to wait until API is enabled
  depends_on = [
    google_cloud_run_v2_job.search_data_index_scheduler,
  ]
}