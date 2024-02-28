variable "CLOUDFLARE_API_TOKEN" {}
variable "CLOUDFLARE_ZONE_ID" {}
variable "CLOUDFLARE_ACCOUNT_ID" {}

provider "cloudflare" {
  api_token = var.CLOUDFLARE_API_TOKEN
}