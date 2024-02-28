resource "google_artifact_registry_repository" "dev_repository" {
  location      = local.gcp_region
  repository_id = "containers"
  description   = "the container images for the dev environment"
  format        = "DOCKER"
}
