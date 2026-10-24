output "realm" {
  value = keycloak_realm.lab.realm
}

output "client_uuid" {
  value = keycloak_openid_client.cimd.id
}

output "service_account_user_id" {
  value = keycloak_openid_client.cimd.service_account_user_id
}

output "spiffe_alias" {
  value = keycloak_spiffe_identity_provider.spiffe.alias
}
