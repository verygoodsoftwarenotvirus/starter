locals {
  api_database_username = "api_db_user"
  public_url            = "api.whatever.dev"
}

resource "google_project_iam_custom_role" "api_server_role" {
  role_id     = "api_server_role"
  title       = "API Server role"
  description = "An IAM role for the API server"
  permissions = [
    "secretmanager.versions.access",
    "cloudsql.instances.connect",
    "cloudsql.instances.get",
    "pubsub.topics.list",
    "pubsub.topics.publish",
    "pubsub.topics.attachSubscription",
    "pubsub.subscriptions.get",
    "pubsub.subscriptions.list",
    "pubsub.subscriptions.consume",
    "cloudtrace.traces.patch",
    "logging.buckets.create",
    "logging.buckets.write",
    "logging.buckets.list",
    "logging.buckets.get",
    "storage.objects.list",
    "storage.objects.get",
    "storage.objects.update",
    "storage.objects.create",
    "storage.objects.delete",
    "storage.objects.get",
  ]
}

resource "google_service_account" "api_user_service_account" {
  account_id   = "api-server"
  display_name = "API Server"
}

resource "google_project_iam_member" "api_user" {
  project = local.project_id
  role    = google_project_iam_custom_role.api_server_role.id
  member  = format("serviceAccount:%s", google_service_account.api_user_service_account.email)
}

resource "google_project_iam_binding" "api_user_service_account_user" {
  project = local.project_id
  role    = "roles/iam.serviceAccountUser"

  members = [
    google_project_iam_member.api_user.member,
  ]
}

resource "google_project_iam_binding" "api_user_cloud_run_admin" {
  project = local.project_id
  role    = "roles/run.admin"

  members = [
    google_project_iam_member.api_user.member,
  ]
}

# this allows the service to be on the public internet
data "google_iam_policy" "public_access" {
  binding {
    role = "roles/run.invoker"
    members = [
      "allUsers",
    ]
  }
}

resource "google_cloud_run_service_iam_policy" "public_access" {
  location    = google_cloud_run_v2_service.api_server.location
  project     = google_cloud_run_v2_service.api_server.project
  service     = google_cloud_run_v2_service.api_server.name
  policy_data = data.google_iam_policy.public_access.policy_data
}

resource "random_password" "api_user_database_password" {
  length           = 64
  special          = true
  override_special = "#$*-_=+[]"
}

resource "google_secret_manager_secret" "api_user_database_password" {
  secret_id = "api_user_database_password"

  replication {
    automatic = true
  }
}

resource "google_secret_manager_secret_version" "api_user_database_password" {
  secret = google_secret_manager_secret.api_user_database_password.id

  secret_data = random_password.api_user_database_password.result
}

resource "google_sql_user" "api_user" {
  name     = local.api_database_username
  instance = google_sql_database_instance.dev.name
  password = random_password.api_user_database_password.result
}

resource "google_cloud_run_v2_service" "api_server" {
  name     = "api-server"
  location = local.gcp_region
  ingress  = "INGRESS_TRAFFIC_ALL"

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [
    google_sql_database_instance.dev,
    google_service_account.api_user_service_account,
    google_secret_manager_secret.api_user_database_password,
    google_secret_manager_secret.cookie_hash_key,
    google_secret_manager_secret.cookie_block_key,
    google_secret_manager_secret.data_changes_topic_name,
    google_secret_manager_secret.sendgrid_api_token,
    google_secret_manager_secret.segment_api_token,
    google_secret_manager_secret.algolia_api_key,
    google_secret_manager_secret.algolia_application_id,
  ]

  template {
    service_account = google_service_account.api_user_service_account.email

    scaling {
      max_instance_count = 1
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [google_sql_database_instance.dev.connection_name]
      }
    }

    volumes {
      name = "config"
      secret {
        secret       = google_secret_manager_secret.api_service_config.secret_id
        default_mode = 256 # 0400
        items {
          version = "latest"
          path    = "service-config.json"
          mode    = 256 # 0400
        }
      }
    }

    containers {
      image = "us-central1-docker.pkg.dev/project-name/containers/api_server"

      resources {
        limits = {
          cpu    = "1"
          memory = "128Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = false
      }

      env {
        name  = "RUNNING_IN_GCP"
        value = "true"
      }

      env {
        name  = "COMPANY_NAME_SERVICE_ENVIRONMENT"
        value = local.environment
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
        name  = "COMPANY_NAME_DATABASE_INSTANCE_CONNECTION_NAME"
        value = google_sql_database_instance.dev.connection_name
      }

      env {
        name  = "COMPANY_NAME_DATABASE_NAME"
        value = local.database_name
      }

      env {
        name  = "COMPANY_NAME_DATABASE_USER"
        value = local.api_database_username
      }

      env {
        name  = "DATA_CHANGES_TOPIC_NAME"
        value = google_pubsub_topic.data_changes_topic.name
      }

      env {
        name  = "CONFIGURATION_FILEPATH"
        value = "/config/service-config.json"
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

      env {
        name = "COMPANY_NAME_COOKIE_HASH_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.cookie_hash_key.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "COMPANY_NAME_COOKIE_BLOCK_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.cookie_block_key.secret_id
            version = "latest"
          }
        }
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

      env {
        name = "COMPANY_NAME_SEGMENT_API_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.segment_api_token.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "COMPANY_NAME_POSTHOG_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.segment_api_token.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "COMPANY_NAME_ALGOLIA_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.algolia_api_key.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "COMPANY_NAME_ALGOLIA_APPLICATION_ID"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.algolia_application_id.secret_id
            version = "latest"
          }
        }
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
        name = "COMPANY_NAME_GOOGLE_SSO_CLIENT_ID"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.google_sso_client_id.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "COMPANY_NAME_GOOGLE_SSO_CLIENT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.google_sso_client_secret.secret_id
            version = "latest"
          }
        }
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      volume_mounts {
        name       = "config"
        mount_path = "/config"
      }
    }
  }
}

resource "google_cloud_run_domain_mapping" "api_server_domain_mapping" {
  location = local.gcp_region
  name     = "api.whatever.dev"

  metadata {
    namespace = local.project_id
  }

  spec {
    route_name = google_cloud_run_v2_service.api_server.name
  }
}

resource "cloudflare_record" "api_cname_record" {
  zone_id = var.CLOUDFLARE_ZONE_ID
  name    = "api.whatever.dev"
  type    = "CNAME"
  value   = "ghs.googlehosted.com"
  ttl     = 1
  proxied = true
  comment = "Managed by Terraform"
}
