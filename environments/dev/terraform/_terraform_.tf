terraform {
  required_version = "1.5.7"

  backend "remote" {
    organization = "your_org_here"

    workspaces {
      name = "dev-backend"
    }
  }
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "4.3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "4.73.1"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "2.2.0"
    }
    algolia = {
      source  = "philippe-vandermoere/algolia"
      version = "0.7.0"
    }
  }
}
