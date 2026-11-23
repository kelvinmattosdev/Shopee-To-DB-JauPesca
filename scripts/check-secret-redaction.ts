import assert from "node:assert/strict";
import { sanitizeErrorMessage, sanitizeSensitiveData } from "../src/services/errorSanitizer.service.js";

const credential = "test-secret-value-not-real";
const sanitized = sanitizeSensitiveData({
    accessToken: credential,
    token: credential,
    nested: { partnerKey: credential, ok: "preserved" },
    url: `https://user:${credential}@example.test/path?access_token=${credential}&page=2`,
});
const serialized = JSON.stringify(sanitized);

assert(!serialized.includes(credential));
assert(serialized.includes("preserved"));
assert(serialized.includes("page=2"));
assert(!sanitizeErrorMessage(`Request failed: partner_key=${credential}`).includes(credential));
assert(!sanitizeErrorMessage(`Request failed: token=${credential}`).includes(credential));
assert(!sanitizeErrorMessage(`Authorization: Bearer ${credential}`).includes(credential));
assert.deepEqual(JSON.parse(sanitizeErrorMessage(`{"token":"${credential}","ok":true}`)), { token: "[REDACTED]", ok: true });
assert.equal(sanitizeErrorMessage(`https://example.test/?token=${credential}&ok=1`), "https://example.test/?token=[REDACTED]&ok=1");
console.log("Secret redaction checks passed.");
