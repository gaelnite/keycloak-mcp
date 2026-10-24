locals {
  # Scopes read by the MCP tool registry (one per tool family).
  tool_scopes = [
    "keycloak.realms.read",
    "keycloak.clients.read",
    "keycloak.users.read",
    "keycloak.groups.read",
    "keycloak.roles.read",
    "keycloak.events.read",
    "keycloak.events.admin.read",
    "keycloak.metrics.read",
    "keycloak.extensions.read",
    "keycloak.orgs.read",
    "keycloak.audit.read",
    "keycloak.config.read",
  ]
  extra_scopes = ["mcp.read", "mcp.write"]
  all_scopes   = concat(local.extra_scopes, local.tool_scopes)
  default_scopes = concat(
    ["profile", "email", "roles", "web-origins"],
    local.all_scopes,
  )
  realm_management_read_roles = [
    "view-realm",
    "view-users",
    "view-clients",
    "view-events",
    "view-identity-providers",
    "view-authorization",
    "query-users",
    "query-groups",
    "query-clients",
  ]
}

resource "keycloak_realm" "lab" {
  realm                 = var.realm
  enabled               = true
  display_name          = "Keycloak MCP"
  ssl_required          = "external"
  revoke_refresh_token  = true
  access_token_lifespan = "300s"
}

resource "keycloak_openid_client_scope" "scope" {
  for_each               = toset(local.all_scopes)
  realm_id               = keycloak_realm.lab.id
  name                   = each.value
  include_in_token_scope = true
  gui_order              = 1
}

resource "keycloak_role" "mcp_admin" {
  realm_id = keycloak_realm.lab.id
  name     = "mcp-admin"
}

resource "keycloak_spiffe_identity_provider" "spiffe" {
  realm           = keycloak_realm.lab.id
  alias           = var.spiffe_alias
  trust_domain    = var.spiffe_trust_domain
  bundle_endpoint = var.spiffe_bundle_endpoint
}

resource "keycloak_openid_client" "cimd" {
  realm_id                     = keycloak_realm.lab.id
  client_id                    = var.cimd_client_id
  name                         = "SPIFFE MCP client"
  enabled                      = true
  access_type                  = "CONFIDENTIAL"
  client_authenticator_type    = "federated-jwt"
  standard_flow_enabled        = false
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = true

  extra_config = {
    "jwt.credential.issuer" = keycloak_spiffe_identity_provider.spiffe.alias
    "jwt.credential.sub"    = var.spiffe_subject
  }
}

resource "keycloak_openid_audience_protocol_mapper" "mcp" {
  realm_id                 = keycloak_realm.lab.id
  client_id                = keycloak_openid_client.cimd.id
  name                     = "aud-mcp"
  included_custom_audience = var.mcp_audience
  add_to_access_token      = true
  add_to_id_token          = false
}

resource "keycloak_openid_client_default_scopes" "cimd" {
  realm_id       = keycloak_realm.lab.id
  client_id      = keycloak_openid_client.cimd.id
  default_scopes = local.default_scopes
}

resource "keycloak_openid_client_service_account_realm_role" "mcp_admin" {
  realm_id                = keycloak_realm.lab.id
  service_account_user_id = keycloak_openid_client.cimd.service_account_user_id
  role                    = keycloak_role.mcp_admin.name
}

data "keycloak_openid_client" "realm_management" {
  realm_id  = keycloak_realm.lab.id
  client_id = "realm-management"
}

resource "keycloak_openid_client_service_account_role" "realm_management_read" {
  for_each                = toset(local.realm_management_read_roles)
  realm_id                = keycloak_realm.lab.id
  service_account_user_id = keycloak_openid_client.cimd.service_account_user_id
  client_id               = data.keycloak_openid_client.realm_management.id
  role                    = each.value
}
