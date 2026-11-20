// Product IDs that are useful in URLs and on disk.
import crypto from "node:crypto";

const ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"; // Crockford-ish, no i/l/o/u

export function newProductId() {
  const bytes = crypto.randomBytes(12);
  let out = "";
  for (const b of bytes) out += ALPHABET[b % ALPHABET.length];
  return `pd_${out}`;
}

export function newEventId() {
  return `ev_${crypto.randomBytes(8).toString("hex")}`;
}

export function isProductId(s) {
  return typeof s === "string" && /^pd_[0-9a-z]{12}$/.test(s);
}
