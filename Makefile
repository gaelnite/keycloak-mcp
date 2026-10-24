KEYCLOAK_URL ?= https://localhost:8443
ANSIBLE ?= ansible-playbook
ANSIBLE_INVENTORY ?= ansible/inventory/hosts.yml
ANSIBLE_ARGS ?=
REALM ?= lab

.PHONY: up down init plan apply policies destroy

up:
	$(ANSIBLE) -i $(ANSIBLE_INVENTORY) ansible/playbooks/site.yml $(ANSIBLE_ARGS)

down:
	$(ANSIBLE) -i $(ANSIBLE_INVENTORY) ansible/playbooks/teardown.yml $(ANSIBLE_ARGS)

init:
	terraform -chdir=terraform init -input=false

plan:
	terraform -chdir=terraform plan -input=false

apply:
	terraform -chdir=terraform apply -input=false

# CIMD client policies need typed booleans/lists. The Keycloak Terraform
# provider stores executor configuration as strings, so this declarative JSON
# is applied through the Admin API instead. The password is passed on stdin.
policies:
	@test -n "$$KEYCLOAK_ADMIN_PASSWORD" || (echo "set KEYCLOAK_ADMIN_PASSWORD" && exit 1)
	@token=$$(printf 'client_id=admin-cli&username=%s&password=%s&grant_type=password' \
	  "$${KEYCLOAK_ADMIN_USER:-admin}" "$$KEYCLOAK_ADMIN_PASSWORD" \
	  | curl -sk -X POST "$(KEYCLOAK_URL)/realms/master/protocol/openid-connect/token" -d @- \
	  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'); \
	curl -sk -o /dev/null -w "profiles %{http_code}\n" -X PUT \
	  -H "Authorization: Bearer $$token" -H "Content-Type: application/json" \
	  "$(KEYCLOAK_URL)/admin/realms/$(REALM)/client-policies/profiles" -d @realm/cimd-profile.json; \
	curl -sk -o /dev/null -w "policies %{http_code}\n" -X PUT \
	  -H "Authorization: Bearer $$token" -H "Content-Type: application/json" \
	  "$(KEYCLOAK_URL)/admin/realms/$(REALM)/client-policies/policies" -d @realm/cimd-policy.json

destroy:
	terraform -chdir=terraform destroy -input=false
