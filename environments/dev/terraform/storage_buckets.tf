resource "google_storage_bucket" "api_media" {
  provider                    = google
  name                        = "media.whatever.dev"
  location                    = "US"
  uniform_bucket_level_access = false
  force_destroy               = true

  versioning {
    enabled = true
  }

  website {
    main_page_suffix = "index.html"
    not_found_page   = "index.html"
  }

  cors {
    origin          = ["https://whatever.dev]"]
    method          = ["GET", "HEAD", "PUT", "POST", "DELETE"]
    response_header = ["*"]
    max_age_seconds = 3600
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age                = 7
      num_newer_versions = 3
    }
  }
}

resource "google_storage_bucket_access_control" "public_rule" {
  bucket = google_storage_bucket.api_media.name
  role   = "READER"
  entity = "allUsers"
}


data "google_iam_policy" "public_policy" {
  binding {
    role = "roles/storage.objectViewer"
    members = [
      "allUsers",
    ]
  }
}

resource "google_storage_bucket_iam_policy" "policy" {
  bucket      = google_storage_bucket.api_media.name
  policy_data = data.google_iam_policy.public_policy.policy_data
}

resource "cloudflare_record" "api_media" {
  zone_id = var.CLOUDFLARE_ZONE_ID
  name    = "media"
  value   = "c.storage.googleapis.com"
  type    = "CNAME"
  proxied = true
  ttl     = 1
  comment = "Managed by Terraform"
}