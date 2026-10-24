terraform {
  required_version = ">= 1.6"

  required_providers {
    keycloak = {
      source  = "keycloak/keycloak"
      version = "~> 5.10"
    }
  }
}

provider "keycloak" {
  url                      = var.keycloak_url
  realm                    = "master"
  client_id                = var.admin_client_id
  username                 = var.admin_username
  password                 = var.admin_password
  tls_insecure_skip_verify = var.tls_insecure_skip_verify
  keycloak_version         = var.keycloak_version
  initial_login            = false
}
