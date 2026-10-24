variable "keycloak_url" {
  description = "Keycloak base URL (no /admin suffix)"
  type        = string
  default     = "https://localhost:8443"
}

variable "admin_client_id" {
  description = "Client used for the password grant"
  type        = string
  default     = "admin-cli"
}

variable "admin_username" {
  description = "Master-realm admin username"
  type        = string
  default     = "admin"
}

variable "admin_password" {
  description = "Master-realm admin password (prefer TF_VAR_admin_password)"
  type        = string
  sensitive   = true
}

variable "keycloak_version" {
  description = "Keycloak version, used when /admin/serverinfo is unavailable"
  type        = string
  default     = "26.8.1"
}

variable "tls_insecure_skip_verify" {
  description = "Allow the self-signed lab certificate (development only)"
  type        = bool
  default     = true
}

variable "realm" {
  description = "Realm to create and manage"
  type        = string
  default     = "lab"
}

variable "cimd_client_id" {
  description = "CIMD URL used as the OAuth client_id"
  type        = string
  default     = "https://localhost:9444/client-metadata.json"
}

variable "mcp_audience" {
  description = "Audience the MCP server expects in access tokens"
  type        = string
  default     = "https://localhost:8800/mcp"
}

variable "spiffe_alias" {
  description = "Keycloak identity-provider alias for the SPIFFE trust domain"
  type        = string
  default     = "spiffe-lab"
}

variable "spiffe_trust_domain" {
  description = "SPIFFE trust domain (spiffe://...)"
  type        = string
  default     = "spiffe://lab.local"
}

variable "spiffe_bundle_endpoint" {
  description = "HTTPS endpoint serving the trust-domain bundle"
  type        = string
  default     = "https://localhost:9444/bundle.json"
}

variable "spiffe_subject" {
  description = "SPIFFE ID the client assertion must carry in sub"
  type        = string
  default     = "spiffe://lab.local/workload/mcp-client"
}
