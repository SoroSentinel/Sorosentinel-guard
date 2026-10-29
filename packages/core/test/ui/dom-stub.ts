import { escapeHtml } from "../../src/wording/sanitize.ts";

/**
 * A DOM stub for the plain-DOM view component (src/ui/findings.ts), so its
 * output can be tested and serialized without a browser and without adding a
 * DOM dependency (§6: dependencies need approval).
 *
 * Only the members the component actually calls are implemented:
 * `createElement`, `createTextNode`, `setAttribute`, `append`. Anything the
 * component starts calling that is not here throws immediately, so a new DOM
 * dependency shows up as a failing test rather than silent nothing.
 */

export interface StubElement {
  readonly kind: "element";
  readonly tag: string;
  readonly attrs: [string, string][];
  readonly children: StubNode[];
  setAttribute(name: string, value: string): void;
  append(...nodes: StubNode[]): void;
}

export interface StubText {
  readonly kind: "text";
  readonly text: string;
}

export type StubNode = StubElement | StubText;

export interface DomStub {
  /** Hand this to the component as its `doc`. */
  readonly doc: Document;
  /** Serializes a stubbed subtree the way a browser would. */
  readonly serialize: (node: StubNode) => string;
  /** Every attribute in the tree whose name ends with `suffix`, in document order. */
  readonly attributes: (node: StubNode, suffix: string) => string[];
  /** Every tag name in the tree, in document order. */
  readonly tags: (node: StubNode) => string[];
  /** Text nodes only: no markup, so this is what a screen reader would read. */
  readonly textOf: (node: StubNode) => string;
}

export function createDomStub(): DomStub {
  const element = (tag: string): StubElement => {
    const node: StubElement = {
      kind: "element",
      tag,
      attrs: [],
      children: [],
      setAttribute(name: string, value: string) {
        const existing = node.attrs.findIndex(([k]) => k === name);
        if (existing === -1) node.attrs.push([name, value]);
        else node.attrs[existing] = [name, value];
      },
      append(...nodes: StubNode[]) {
        for (const child of nodes) {
          if (child.kind !== "element" && child.kind !== "text") throw new TypeError("append accepts nodes only");
          node.children.push(child);
        }
      },
    };
    return node;
  };

  const serialize = (node: StubNode): string => {
    if (node.kind === "text") return escapeHtml(node.text);
    const attrs = node.attrs.map(([k, v]) => ` ${k}="${escapeHtml(v)}"`).join("");
    // Attribute values are escaped above; a real browser escapes `"` and `&` the same way.
    return `<${node.tag}${attrs}>${node.children.map(serialize).join("")}</${node.tag}>`;
  };

  const walk = (node: StubNode, out: (n: StubNode) => void): void => {
    out(node);
    if (node.kind === "element") for (const child of node.children) walk(child, out);
  };

  const doc = {
    createElement(tag: string) {
      return element(tag);
    },
    createTextNode(text: string) {
      if (typeof text !== "string") throw new TypeError(`createTextNode needs a string, got ${typeof text}`);
      return { kind: "text", text } satisfies StubText;
    },
  } as unknown as Document;

  return {
    doc,
    serialize,
    attributes: (node, suffix) => {
      const out: string[] = [];
      walk(node, (n) => {
        if (n.kind === "element") for (const [k, v] of n.attrs) if (k.endsWith(suffix)) out.push(v);
      });
      return out;
    },
    tags: (node) => {
      const out: string[] = [];
      walk(node, (n) => {
        if (n.kind === "element") out.push(n.tag);
      });
      return out;
    },
    textOf: (node) => {
      const parts: string[] = [];
      walk(node, (n) => {
        if (n.kind === "text") parts.push(n.text);
      });
      return parts.join(" ");
    },
  };
}
