variable "ALGOLIA_APPLICATION_ID" {}
variable "ALGOLIA_API_KEY" {}

provider "algolia" {
  application_id = var.ALGOLIA_APPLICATION_ID
  api_key        = var.ALGOLIA_API_KEY
}
