import { describe, expect, it } from "vitest";

import { MAX_DISPLAY_LENGTH, escapeHtml, sanitizeHexBytes, sanitizeUntrusted } from "../src/index.ts";

const hexOf = (s: string) => Array.from(new TextEncoder().encode(s), (b) => b.toString(16).padStart(2, "0")).join("");

describe("sanitizeUntrusted", () => {
  it("keeps ordinary text, including non-Latin scripts", () => {
    expect(sanitizeUntrusted("Invoice 42")).toBe("Invoice 42");
    expect(sanitizeUntrusted("Café ありがとう")).toBe("Café ありがとう");
  });

  it.each([
    ["right-to-left override (filename spoof)", "invoice‮txt.exe", "invoicetxt.exe"],
    ["isolates", "a⁦b⁧c⁨d⁩e", "abcde"],
    ["LRM / RLM / Arabic letter mark", "a‎b‏c؜d", "abcd"],
    ["zero-width characters", "pay​pal‌‍⁠﻿", "paypal"],
    ["newlines and tabs (fake extra lines)", "Memo\nSend to: GABC\t!", "MemoSend to: GABC!"],
    ["C1 controls and DEL", "a\u0085b\u009Bc\u007Fd", "abcd"],
    ["NUL", "a\u0000b", "ab"],
  ])("removes %s", (_n, input, want) => {
    expect(sanitizeUntrusted(input)).toBe(want);
  });

  it("shows invalid UTF-8 as replacement characters instead of dropping it", () => {
    expect(sanitizeUntrusted(new Uint8Array([0x41, 0xff, 0x42]))).toBe("A�B");
  });

  it("caps length and marks the cut", () => {
    const out = sanitizeUntrusted("x".repeat(10_000));
    expect([...out]).toHaveLength(MAX_DISPLAY_LENGTH);
    expect(out.endsWith("…")).toBe(true);
    expect(sanitizeUntrusted("x".repeat(MAX_DISPLAY_LENGTH))).toBe("x".repeat(MAX_DISPLAY_LENGTH));
  });

  it("counts code points, so astral characters are never split", () => {
    const out = sanitizeUntrusted("😀".repeat(MAX_DISPLAY_LENGTH + 5));
    expect([...out].slice(0, -1).every((c) => c === "😀")).toBe(true);
  });
});

describe("sanitizeHexBytes", () => {
  it("decodes memo bytes and sanitizes them", () => {
    expect(sanitizeHexBytes(hexOf("hi‮there"))).toBe("hithere");
  });

  it.each(["abc", "zz", "AB"])("returns empty text for malformed hex %j", (h) => {
    expect(sanitizeHexBytes(h)).toBe("");
  });
});

describe("escapeHtml", () => {
  it("escapes markup so untrusted text cannot become HTML", () => {
    expect(escapeHtml(sanitizeUntrusted(`<a href="x">click</a> & 'q'`))).toBe(
      "&lt;a href=&quot;x&quot;&gt;click&lt;/a&gt; &amp; &#39;q&#39;",
    );
  });
});
