locals {
  database_name = "service-name"
}

resource "google_sql_database_instance" "dev" {
  name                = "dev"
  database_version    = "POSTGRES_15"
  region              = local.gcp_region
  deletion_protection = false

  settings {
    tier                  = "db-f1-micro"
    disk_size             = 20
    disk_autoresize       = true
    disk_autoresize_limit = 50

    insights_config {
      query_insights_enabled  = true
      query_string_length     = 4096
      record_application_tags = false
      record_client_address   = false
    }

    ip_configuration {
      require_ssl = false
    }

    maintenance_window {
      day          = 7
      hour         = 3
      update_track = "stable"
    }
  }
}

resource "google_sql_ssl_cert" "client_cert" {
  common_name = "project-name"
  instance    = google_sql_database_instance.dev.name
}

resource "google_sql_database" "api_database" {
  name     = local.database_name
  instance = google_sql_database_instance.dev.name
}
