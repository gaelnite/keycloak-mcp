#!/usr/bin/env node
// Cedar PDP for the Keycloak MCP reference server.
//
// One JSON request per line on stdin, one JSON response per line on stdout. Loads
// and validates the schema/policies/entities once, names policies by their @id
// annotation, and returns the bundle hash with every decision. Any failure is
// {ok:false}; the Python PEP fails closed.
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  getCedarVersion,
  isAuthorized,
  policySetTextToParts,
  validate,
} from "@cedar-policy/cedar-wasm/nodejs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CEDAR = path.resolve(HERE, "..", "cedar");

function emit(payload) {
  process.stdout.write(JSON.stringify(payload) + "\n");
}
function fail(code, detail) {
  emit({ ok: false, error: code, detail });
  process.exit(3);
}

let schema;
let policyText;
let entitiesRaw;
try {
  schema = fs.readFileSync(path.join(CEDAR, "schema.cedarschema"), "utf8");
  policyText = fs.readFileSync(path.join(CEDAR, "policies.cedar"), "utf8");
  entitiesRaw = fs.readFileSync(path.join(CEDAR, "entities.json"), "utf8");
} catch (error) {
  fail("read_error", String(error));
}

let entities;
try {
  entities = JSON.parse(entitiesRaw);
} catch (error) {
  fail("entities_json", String(error));
}

const parsed = policySetTextToParts(policyText);
if (parsed.type !== "success") fail("policy_parse", JSON.stringify(parsed.errors));
const staticPolicies = {};
for (const policyPart of parsed.policies) {
  const match = policyPart.match(/@id\("([^"]+)"\)/);
  if (!match) fail("missing_policy_id", policyPart.slice(0, 120));
  if (staticPolicies[match[1]]) fail("duplicate_policy_id", match[1]);
  staticPolicies[match[1]] = policyPart;
}
const policies = { staticPolicies };
const validation = validate({ schema, policies });
if (validation.type !== "success" || (validation.validationErrors || []).length > 0) {
  fail("policy_validation", JSON.stringify(validation.validationErrors || validation.errors || []));
}

const bundleHash = crypto
  .createHash("sha256")
  .update(schema)
  .update("\0")
  .update(policyText)
  .update("\0")
  .update(entitiesRaw)
  .digest("hex");

const meta = {
  cedarVersion: getCedarVersion(),
  bundleHash,
  policyIds: Object.keys(staticPolicies).sort(),
};

function authorize(request) {
  const call = {
    principal: request.principal,
    action: request.action,
    resource: request.resource,
    context: request.context || {},
    schema,
    policies,
    entities,
    validateRequest: true,
  };
  let answer;
  try {
    answer = isAuthorized(call);
  } catch (error) {
    return { ok: false, error: "pdp_error", detail: String(error) };
  }
  if (answer.type === "failure") {
    return { ok: false, error: "pdp_failure", errors: answer.errors };
  }
  return {
    ok: true,
    decision: answer.response.decision,
    determiningPolicies: answer.response.diagnostics.reason,
    errors: (answer.response.diagnostics.errors || []).map((item) => ({
      policyId: item.policyId,
      message: item.error ? item.error.message : String(item),
    })),
    warnings: answer.warnings || [],
  };
}

const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on("line", (line) => {
  if (!line.trim()) return;
  let request;
  try {
    request = JSON.parse(line);
  } catch (error) {
    emit({ ok: false, error: "bad_json", detail: String(error) });
    return;
  }
  const requestId = request.requestId === undefined ? null : request.requestId;
  if (request.op === "ping") {
    emit({ ok: true, requestId, ...meta });
    return;
  }
  if (request.op === "validate") {
    emit({ ok: true, requestId, valid: validation.type === "success", bundleHash });
    return;
  }
  if (request.op === "authorize") {
    emit({ requestId, bundleHash, cedarVersion: meta.cedarVersion, ...authorize(request) });
    return;
  }
  emit({ ok: false, requestId, error: "unknown_op" });
});
lines.on("close", () => process.exit(0));
