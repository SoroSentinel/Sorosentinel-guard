/**
 * Blocklist matching, ported from sorosentinel-intel internal/wording
 * (compileBlocklist, BlockedTerms). Matches must agree with Go's regexp:
 *
 * - Go's `(?i)` folds case with Unicode simple folding, so `k` also matches
 *   U+212A KELVIN SIGN and `s` also matches U+017F LONG S. JS `i` differs, so
 *   letters are expanded into explicit classes instead.
 * - Go's `\b` and `\s` are ASCII-only; JS's are not, so both are spelled out.
 */

const WORD = "[0-9A-Za-z_]";
const BOUNDARY = `(?:(?<=${WORD})(?!${WORD})|(?<!${WORD})(?=${WORD}))`;
// Go's \s is [\t\n\f\r ].
const SEPARATOR = "[\\t\\n\\f\\r \\-_]+";
// Go's (?i)[a-z].
const ANY_LETTER = "[A-Za-z\\u017F\\u212A]";
const SUFFIX = `${ANY_LETTER}?(?:${["s", "es", "ed", "ly", "ing", "er", "ers"].map(literal).join("|")})?`;

/** Compiles the blocklist. Throws on an empty list or term. */
export function compileBlocklist(terms: readonly string[]): RegExp {
  if (terms.length === 0) throw new Error("blocklist is empty");
  const parts = terms.map((term) => {
    const words = goFields(term.toLowerCase());
    if (words.length === 0) throw new Error("blocklist has an empty term");
    // Go would fold non-ASCII letters too; refuse rather than approximate.
    if (/[^\x00-\x7f]/.test(term)) throw new Error("blocklist terms must be ASCII");
    // One optional extra letter covers doubled consonants ("scammed"); errs toward blocking.
    return words.map(literal).join(SEPARATOR) + SUFFIX;
  });
  return new RegExp(`${BOUNDARY}(?:${parts.join("|")})${BOUNDARY}`, "gu");
}

/** Distinct blocklisted terms found in text, lowercased and sorted. */
export function findBlockedTerms(blocked: RegExp, text: string): string[] {
  const seen = new Set<string>();
  for (const m of text.matchAll(blocked)) seen.add(m[0].toLowerCase());
  return [...seen].sort();
}

/** One ASCII term as a case-insensitive pattern, the way Go's (?i) folds it. */
function literal(word: string): string {
  let out = "";
  for (const ch of word) {
    switch (ch) {
      case "k":
        out += "[Kk\\u212A]";
        break;
      case "s":
        out += "[Ss\\u017F]";
        break;
      default:
        out += /[a-z]/.test(ch) ? `[${ch.toUpperCase()}${ch}]` : ch.replace(/[\\^$.*+?()[\]{}|/-]/g, "\\$&");
    }
  }
  return out;
}

/** strings.Fields: splits on runs of unicode.IsSpace. */
export function goFields(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  for (const ch of s) {
    if (isGoSpace(ch.codePointAt(0) ?? 0)) {
      if (cur !== "") out.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur !== "") out.push(cur);
  return out;
}

/** unicode.IsSpace. */
export function isGoSpace(cp: number): boolean {
  return (
    (cp >= 0x09 && cp <= 0x0d) ||
    cp === 0x20 ||
    cp === 0x85 ||
    cp === 0xa0 ||
    cp === 0x1680 ||
    (cp >= 0x2000 && cp <= 0x200a) ||
    cp === 0x2028 ||
    cp === 0x2029 ||
    cp === 0x202f ||
    cp === 0x205f ||
    cp === 0x3000
  );
}

const MAX_BLOCKLIST_BYTES = 64 << 10;

/**
 * Reads Intel's wording/blocklist.yaml. This is not a YAML parser: it accepts
 * only the shape Intel publishes (comment lines, blank lines, `terms:`, then
 * `  - term` items of plain ASCII words) and throws on anything else, so a
 * format change upstream fails loud instead of being misread.
 */
export function parseBlocklistYaml(source: string): string[] {
  if (new TextEncoder().encode(source).length > MAX_BLOCKLIST_BYTES) throw new Error("blocklist.yaml is too large");
  const terms: string[] = [];
  let inTerms = false;
  const lines = source.split("\n");
  for (const [i, raw] of lines.entries()) {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (line.trim() === "" || /^#/.test(line)) continue;
    if (!inTerms && line === "terms:") {
      inTerms = true;
      continue;
    }
    const item = /^ {2}- ([a-z][a-z ]*[a-z]|[a-z])$/.exec(line);
    if (!inTerms || item === null || item[1] === undefined) {
      throw new Error(`blocklist.yaml:${i + 1}: unsupported line`);
    }
    terms.push(item[1]);
  }
  if (!inTerms) throw new Error("blocklist.yaml: no terms key");
  return terms;
}
