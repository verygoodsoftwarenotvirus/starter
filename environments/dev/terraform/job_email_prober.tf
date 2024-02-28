resource "google_project_iam_custom_role" "email_prober_role" {
  role_id     = "email_prober_role"
  title       = "email prober role"
  description = "An IAM role for the email prober"
  permissions = [
    "secretmanager.versions.access",
    "eventarc.events.receiveAuditLogWritten",
    "eventarc.events.receiveEvent",
    "run.jobs.run",
    "run.routes.invoke",
    "artifactregistry.dockerimages.get",
    "artifactregistry.dockerimages.list",
  ]
}

resource "google_service_account" "email_prober_user_service_account" {
  account_id   = "email-prober"
  display_name = "Email Prober"
}

resource "google_project_iam_member" "email_prober_user" {
  project = local.project_id
  role    = google_project_iam_custom_role.email_prober_role.id
  member  = format("serviceAccount:%s", google_service_account.email_prober_user_service_account.email)
}

resource "google_cloud_run_v2_job" "email_prober" {
  name     = "email-prober"
  location = local.gcp_region

  template {
    task_count  = 1
    parallelism = 1

    template {
      execution_environment = "EXECUTION_ENVIRONMENT_GEN2"
      max_retries           = 1
      service_account       = google_service_account.email_prober_user_service_account.email

      containers {
        image = format("%s-docker.pkg.dev/%s/%s/email-prober", local.gcp_region, local.project_id, google_artifact_registry_repository.dev_repository.name)

        resources {
          limits = {
            cpu    = "1"
            memory = "512Mi"
          }
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
          name = "COMPANY_NAME_SENDGRID_API_TOKEN"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.sendgrid_api_token.secret_id
              version = "latest"
            }
          }
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

resource "google_cloud_scheduler_job" "run_email_prober" {
  name             = "email-prober-schedule"
  description      = "Runs the email prober once a month"
  schedule         = "30 1 1,15 * *"
  time_zone        = "America/Chicago"
  attempt_deadline = "320s"

  retry_config {
    retry_count = 1
  }


  http_target {
    http_method = "POST"
    uri         = "https://${google_cloud_run_v2_job.email_prober.location}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${data.google_project.project.number}/jobs/${google_cloud_run_v2_job.email_prober.name}:run"

    oauth_token {
      service_account_email = google_service_account.email_prober_user_service_account.email
    }
  }

  # Use an explicit depends_on clause to wait until API is enabled
  depends_on = [
    google_cloud_run_v2_job.email_prober,
  ]
}