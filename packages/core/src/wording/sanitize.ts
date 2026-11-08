/**
 * Untrusted strings (memo text, asset codes, home domains, stellar.toml fields)
 * can carry control characters, bidirectional overrides or invisible
 * characters that make displayed text say something other than what it is
 * (ARCHITECTURE §17 EC9). Everything shown to a user passes through here first.
 * The result is plain text: integrators must still escape it for their output
 * context (escapeHtml below for HTML) and must never turn it into a link.
 */

/** Longest untrusted string shown, in code points. Longer input is cut and marked. */
export const MAX_DISPLAY_LENGTH = 256;

const ELLIPSIS = "…";

/**
 * Matches Unicode control (Cc), format (Cf, including bidi controls, invisible tags,
 * soft hyphens, zero-width characters), line separator (Zl), and paragraph separator (Zp).
 */
export const UNICODE_UNSAFE_REGEX = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

/**
 * Returns display-safe plain text. Bytes are decoded as UTF-8 with invalid
 * sequences shown as U+FFFD (never silently dropped), unsafe characters are
 * removed, and the result is capped at MAX_DISPLAY_LENGTH code points.
 */
export function sanitizeUntrusted(input: string | Uint8Array): string {
  const text = typeof input === "string" ? input : new TextDecoder("utf-8", { fatal: false }).decode(input);
  const stripped = text.replace(UNICODE_UNSAFE_REGEX, "");
  const codePoints = Array.from(stripped);
  return codePoints.length > MAX_DISPLAY_LENGTH
    ? codePoints.slice(0, MAX_DISPLAY_LENGTH - 1).join("") + ELLIPSIS
    : stripped;
}

/** Decodes a hex string of raw bytes (e.g. Memo.bytesHex) and sanitizes it. Malformed hex yields "". */
export function sanitizeHexBytes(hex: string): string {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) return "";
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return sanitizeUntrusted(bytes);
}

/** Escapes sanitized text for an HTML text or attribute context. */
export function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
