# how to use these resources: https://github.com/philippe-vandermoere/terraform-provider-algolia/blob/11d9e162be54c66c92376ae5647f7f3bd675755a/examples/main.tf

locals {
  default_algolia_ranking_criteria = ["custom", "exact", "typo", "words", "attribute", "filters", "proximity"]
}

resource "algolia_index" "users_index" {
  name = "users"

  searchable_attributes = [
    "username",
  ]
}
