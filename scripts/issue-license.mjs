#!/usr/bin/env node
// Issues a signed Infra Hub Center license key for a paid plan.
//
//   node scripts/issue-license.mjs --plan team --licensee "Acme Pvt Ltd" --expires 2027-09-30 \
//     --key /path/to/infrahub-license-signing.pem
//
// The customer sets the printed key as INFRAHUB_LICENSE_KEY on their API.
// The signing key is Infra Hub Center's private key -- keep it out of every
// repository; the API only holds the matching public key
// (internal/services/license.go).

import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith("--") ? [...acc, [a.slice(2), all[i + 1]]] : acc), [])
);
const plans = ["team", "business", "enterprise"];
if (!plans.includes(args.plan) || !args.licensee || !args.key) {
  console.error(`usage: issue-license.mjs --plan ${plans.join("|")} --licensee NAME [--expires YYYY-MM-DD] --key SIGNING_KEY.pem`);
  process.exit(1);
}
if (args.expires && !/^\d{4}-\d{2}-\d{2}$/.test(args.expires)) {
  console.error("--expires must be YYYY-MM-DD");
  process.exit(1);
}

const payload = Buffer.from(JSON.stringify({ plan: args.plan, licensee: args.licensee, expires: args.expires ?? "" })).toString("base64url");
const key = createPrivateKey(readFileSync(args.key));
const signature = sign(null, Buffer.from(`IHC1.${payload}`), key).toString("base64url");
console.log(`IHC1.${payload}.${signature}`);
