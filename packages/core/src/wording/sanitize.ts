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

/** True for code points that are removed before display. */
function isUnsafe(cp: number): boolean {
  return (
    cp < 0x20 || // C0 controls, including tab and newline
    cp === 0x7f || // DEL
    (cp >= 0x80 && cp <= 0x9f) || // C1 controls
    cp === 0x061c || // Arabic letter mark
    cp === 0x200e || cp === 0x200f || // LRM, RLM
    (cp >= 0x202a && cp <= 0x202e) || // LRE, RLE, PDF, LRO, RLO
    (cp >= 0x2066 && cp <= 0x2069) || // LRI, RLI, FSI, PDI
    (cp >= 0x200b && cp <= 0x200d) || // zero-width space, non-joiner, joiner
    cp === 0x2060 || // word joiner
    cp === 0xfeff // zero-width no-break space / BOM
  );
}

/**
 * Returns display-safe plain text. Bytes are decoded as UTF-8 with invalid
 * sequences shown as U+FFFD (never silently dropped), unsafe characters are
 * removed, and the result is capped at MAX_DISPLAY_LENGTH code points.
 */
export function sanitizeUntrusted(input: string | Uint8Array): string {
  const text = typeof input === "string" ? input : new TextDecoder("utf-8", { fatal: false }).decode(input);
  const kept: string[] = [];
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (!isUnsafe(cp)) kept.push(ch);
  }
  return kept.length > MAX_DISPLAY_LENGTH ? kept.slice(0, MAX_DISPLAY_LENGTH - 1).join("") + ELLIPSIS : kept.join("");
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
