import { sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import type { KeyObject } from "node:crypto";

// For Ed25519, Node's crypto.sign / crypto.verify require `algorithm = null`
// and operate on the message directly (Ed25519 does its own pre-hash).
export function signEd25519(privateKey: KeyObject, message: Buffer): string {
  const sig = cryptoSign(null, message, privateKey);
  return base64UrlNoPad(sig);
}

export function verifyEd25519(
  publicKey: KeyObject,
  message: Buffer,
  sigBase64Url: string,
): boolean {
  const sig = base64UrlDecode(sigBase64Url);
  return cryptoVerify(null, message, publicKey, sig);
}

export function base64UrlNoPad(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function base64UrlDecode(s: string): Buffer {
  const pad = (4 - (s.length % 4)) % 4;
  const b64 =
    s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return Buffer.from(b64, "base64");
}
