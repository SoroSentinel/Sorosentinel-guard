import { assertNever } from "../assert-never.ts";
import type { AnalysisResult, AnalysisStatus } from "../analyze.ts";
import type { AccountEffect, Assurance, BalanceEffect } from "../effects/types.ts";
import type { Finding, Severity } from "../rules/types.ts";
import type { SimulationOutcome } from "../simulate/simulate.ts";
import type { RenderResult, Statement } from "../wording/render.ts";
import { isPlainHttpsUrl } from "../wording/render.ts";
import { sanitizeHexBytes, sanitizeUntrusted } from "../wording/sanitize.ts";

/**
 * Reference findings view (PRD G-12, Guard #46): a framework-neutral plain-DOM
 * component for one `AnalysisResult`.
 *
 * It writes no prose. Sentences come only from the injected `statementFor`
 * renderer; when there is no renderer or a render failed, the finding's
 * structured facts are shown instead, so a wording failure degrades to data and
 * never to reassurance (AGENTS.md §3.2, §5). Field labels are the only text the
 * component supplies; they are names, never statements about a transaction.
 *
 * Strings reach the screen through `createTextNode` (never `innerHTML`) after
 * `sanitizeUntrusted`, so untrusted values cannot become markup or carry control
 * or bidi characters. Nothing untrusted is ever made into a link: the only
 * anchors are the renderer's own configured URLs, revalidated here.
 *
 * Amounts are shown as the integers the API reports, in stroops. No decimal
 * scaling is applied: `BalanceEffect` amounts for a contract-reported token can
 * be in that token's own units, and rendering them as scaled XLM would state a
 * number the ledger does not (§3.8, §3.11). TODO(verify): per-asset decimals.
 */

/** Field names shown to a user. No sentences and no claim about a transaction or entity. */
export interface FindingsLabels {
  readonly region: string;
  readonly status: string;
  readonly reason: string;
  readonly operations: string;
  readonly transactionHash: string;
  readonly network: string;
  readonly snapshot: string;
  readonly effects: string;
  readonly accountChanges: string;
  readonly findings: string;
  readonly facts: string;
  readonly notChecked: string;
  readonly simulation: string;
  readonly account: string;
  readonly asset: string;
  readonly deltaMin: string;
  readonly deltaMax: string;
  readonly assurance: string;
  readonly unbounded: string;
  readonly none: string;
  readonly methodology: string;
  readonly review: string;
}

export const DEFAULT_LABELS: FindingsLabels = {
  region: "Transaction review",
  status: "Status",
  reason: "Reason",
  operations: "Operations",
  transactionHash: "Transaction hash",
  network: "Network",
  snapshot: "Snapshot",
  effects: "Balance effects",
  accountChanges: "Account changes",
  findings: "Findings",
  facts: "Facts",
  notChecked: "Not checked",
  simulation: "Simulation",
  account: "Account",
  asset: "Asset",
  deltaMin: "Worst case",
  deltaMax: "Upper bound",
  assurance: "Assurance",
  unbounded: "no upper bound",
  none: "none",
  methodology: "Methodology",
  review: "Review",
};

// Every Guard status by name; invariant §3.1 forbids a word meaning "safe".
const STATUS_LABELS: Record<AnalysisStatus, string> = {
  findings_present: "Findings present",
  no_issues_found: "No issues found",
  partial: "Partial",
  unanalyzable: "Unanalyzable",
};

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** `assurance` values are shown as the codes themselves: contract-reported is never labelled ledger truth. */
const ASSURANCE_LABELS: Record<Assurance, string> = {
  ledger: "ledger",
  contract_reported: "contract_reported",
};

export interface FindingsOptions {
  /** Document to build nodes in, so the component is testable without a browser. */
  readonly doc: Document;
  /**
   * Approved prose, from the wording renderer. Absent means facts only, and so
   * does any failed result (`not_approved` today: Guard's templates are draft).
   */
  readonly statementFor?: ((finding: Finding) => RenderResult) | undefined;
  /** Overrides any field name. Values are treated as untrusted, like every other string here. */
  readonly labels?: Partial<FindingsLabels>;
  /**
   * Heading level of the region title, clamped to 1..4 (nested levels follow,
   * capped at 6). A page that already has an `h2` should pass 3 so the outline
   * has no skipped levels.
   */
  readonly headingLevel?: number;
}

/** Builds the view for one analysis result. Pure: it attaches nothing to a page. */
export function renderFindings(result: AnalysisResult, options: FindingsOptions): HTMLElement {
  const view = new View(options);
  const root = view.el("section");
  root.setAttribute("role", "region");
  root.setAttribute("data-guard", "findings");
  root.setAttribute("data-status", result.status);
  root.setAttribute("aria-label", view.sanitize(view.labels.region));

  root.append(view.heading(view.heading1, view.labels.region));

  // role=status is the only live region: a re-render announces the headline,
  // not the whole view.
  const status = view.el("p", "guard-status");
  status.setAttribute("role", "status");
  view.text(status, `${view.labels.status}: ${STATUS_LABELS[result.status]}`);
  root.append(status);

  const meta = view.el("dl", "guard-meta");
  view.pair(meta, view.labels.operations, String(result.operationCount));
  view.pair(meta, view.labels.transactionHash, result.txHash ?? view.labels.none);
  view.pair(meta, view.labels.network, result.network);
  view.pair(meta, view.labels.snapshot, result.snapshotStatus);
  if (result.unanalyzableReason !== undefined) view.pair(meta, view.labels.reason, result.unanalyzableReason);
  root.append(meta);

  if (result.effects.length > 0) root.append(view.effectTable(result.effects));
  if (result.accountEffects.length > 0) root.append(view.accountEffects(result.accountEffects));
  root.append(view.findings(result.findings));
  if (result.notChecked.length > 0) root.append(view.codeList(view.labels.notChecked, result.notChecked));
  if (result.simulation !== undefined) root.append(view.simulation(result.simulation));

  return root;
}

/** Shared context: document, merged labels, heading depth, and the renderer hook. */
class View {
  readonly doc: Document;
  readonly labels: FindingsLabels;
  readonly heading1: number;
  readonly heading2: number;
  readonly heading3: number;
  readonly statementFor: ((finding: Finding) => RenderResult) | undefined;

  constructor(options: FindingsOptions) {
    this.doc = options.doc;
    this.labels = { ...DEFAULT_LABELS, ...options.labels };
    const level = Math.min(4, Math.max(1, Math.trunc(options.headingLevel ?? 2)));
    this.heading1 = level;
    this.heading2 = Math.min(6, level + 1);
    this.heading3 = Math.min(6, level + 2);
    this.statementFor = options.statementFor;
  }

  /** The only path from a value to the screen: strip unsafe characters, then a text node. */
  sanitize(value: string): string {
    return sanitizeUntrusted(value);
  }

  text(node: Element, value: string): void {
    node.append(this.doc.createTextNode(this.sanitize(value)));
  }

  el(tag: string, className?: string): HTMLElement {
    const node = this.doc.createElement(tag);
    if (className !== undefined) node.setAttribute("class", className);
    return node;
  }

  heading(level: number, label: string): HTMLElement {
    const node = this.el(`h${String(level)}`);
    this.text(node, label);
    return node;
  }

  pair(dl: Element, name: string, value: string): void {
    const dt = this.el("dt");
    this.text(dt, name);
    const dd = this.el("dd");
    this.text(dd, value);
    dl.append(dt, dd);
  }

  /** A named region with a heading and a `<ul>` of verbatim codes. */
  codeList(label: string, codes: readonly string[]): HTMLElement {
    const section = this.region(label);
    section.append(this.heading(this.heading2, label));
    const ul = this.el("ul");
    for (const code of codes) {
      const li = this.el("li");
      this.text(li, code);
      ul.append(li);
    }
    section.append(ul);
    return section;
  }

  region(label: string): HTMLElement {
    const section = this.el("section");
    section.setAttribute("aria-label", this.sanitize(label));
    return section;
  }

  effectTable(effects: readonly BalanceEffect[]): HTMLElement {
    const section = this.region(this.labels.effects);
    const table = this.el("table");
    const caption = this.el("caption");
    this.text(caption, this.labels.effects);
    const head = this.el("tr");
    for (const label of [
      this.labels.account,
      this.labels.asset,
      this.labels.deltaMin,
      this.labels.deltaMax,
      this.labels.assurance,
    ]) {
      const th = this.el("th");
      th.setAttribute("scope", "col");
      this.text(th, label);
      head.append(th);
    }
    const thead = this.el("thead");
    thead.append(head);
    const tbody = this.el("tbody");
    // Row order is the order analyze returns: worst case first (effects/derive.ts).
    for (const e of effects) {
      const row = this.el("tr");
      for (const value of [
        e.account,
        e.asset,
        e.deltaMin.toString(),
        // null means no upper bound, never zero (§3.9): said so, not implied.
        e.deltaMax === null ? this.labels.unbounded : e.deltaMax.toString(),
        ASSURANCE_LABELS[e.assurance],
      ]) {
        const td = this.el("td");
        this.text(td, value);
        row.append(td);
      }
      tbody.append(row);
    }
    table.append(caption, thead, tbody);
    section.append(this.heading(this.heading2, this.labels.effects), table);
    return section;
  }

  accountEffects(effects: readonly AccountEffect[]): HTMLElement {
    const section = this.region(this.labels.accountChanges);
    section.append(this.heading(this.heading2, this.labels.accountChanges));
    const ul = this.el("ul");
    for (const e of effects) {
      const li = this.el("li");
      const dl = this.el("dl");
      // `dt` names are the API's own field identifiers, so an integrator can map a
      // screen-reader row back to the typed result; section titles use labels.
      this.pair(dl, "kind", e.kind);
      this.pair(dl, "operation_index", String(e.operationIndex));
      this.pair(dl, "account", e.account);
      for (const [name, value] of accountEffectFields(e)) this.pair(dl, name, value);
      li.append(dl);
      ul.append(li);
    }
    section.append(ul);
    return section;
  }

  /** Severity-ordered findings, all of them: the list is never truncated (§7c). */
  findings(findings: readonly Finding[]): HTMLElement {
    const section = this.region(this.labels.findings);
    section.append(this.heading(this.heading2, `${this.labels.findings} (${String(findings.length)})`));
    const ol = this.el("ol");
    if (findings.length === 0) {
      const li = this.el("li");
      this.text(li, this.labels.none);
      ol.append(li);
    }
    for (const f of findings) ol.append(this.findingItem(f));
    section.append(ol);
    return section;
  }

  findingItem(f: Finding): HTMLElement {
    const li = this.el("li");
    li.setAttribute("data-severity", f.severity);
    li.setAttribute("data-code", this.sanitize(f.code));
    li.append(this.heading(this.heading3, `${SEVERITY_LABELS[f.severity]} ${this.sanitize(f.code)}`));

    const rendered = this.statementFor === undefined ? null : this.statementFor(f);
    if (rendered !== null && rendered.ok === true) {
      li.setAttribute("data-wording", "shown");
      const prose = this.el("p");
      this.text(prose, rendered.statement.text);
      const attribution = this.el("p");
      attribution.setAttribute("data-role", "attribution");
      this.text(attribution, rendered.statement.attribution);
      li.append(prose, attribution, this.factsDisclosure(rendered.statement, f));
      this.links(li, rendered.statement);
    } else {
      // Fail closed: codes and facts, no prose. `WordingError.detail` is for logs,
      // so the wording code rides as an attribute instead of becoming user text.
      const code = rendered === null ? "no_renderer" : rendered.ok === false ? rendered.error.code : "unreachable";
      li.setAttribute("data-wording", code);
      li.append(this.factsList(f));
    }
    return li;
  }

  /** The finding's own facts, plus `operation_index`, which every finding has. */
  factsList(f: Finding, extra: Readonly<Record<string, string>> = {}): HTMLElement {
    const dl = this.el("dl");
    dl.setAttribute("data-role", "facts");
    const index = f.operationIndex === null ? this.labels.none : String(f.operationIndex);
    const merged: Record<string, string> = { operation_index: index, ...extra, ...f.facts };
    for (const [name, value] of Object.entries(merged)) this.pair(dl, name, value);
    return dl;
  }

  factsDisclosure(statement: Statement, f: Finding): HTMLElement {
    const details = this.el("details");
    const summary = this.el("summary");
    this.text(summary, this.labels.facts);
    details.append(summary, this.factsList(f, statement.facts));
    return details;
  }

  links(li: Element, statement: Statement): void {
    for (const [url, label] of [
      [statement.methodologyUrl, this.labels.methodology],
      [statement.reviewUrl, this.labels.review],
    ] as const) {
      if (!isPlainHttpsUrl(url)) continue;
      const a = this.el("a");
      a.setAttribute("href", url);
      a.setAttribute("rel", "noreferrer");
      this.text(a, label);
      li.append(a);
    }
  }

  simulation(outcome: SimulationOutcome): HTMLElement {
    const section = this.region(this.labels.simulation);
    section.append(this.heading(this.heading2, this.labels.simulation));
    const dl = this.el("dl");
    this.pair(dl, "status", outcome.status);
    switch (outcome.status) {
      case "ok":
        this.pair(dl, "latest_ledger", String(outcome.latestLedger));
        this.pair(dl, "min_resource_fee_stroops", outcome.minResourceFee);
        this.pair(dl, "resource_fee_stroops", outcome.resourceFee);
        this.pair(dl, "footprint_read_only", String(outcome.footprint.readOnly));
        this.pair(dl, "footprint_read_write", String(outcome.footprint.readWrite));
        this.pair(dl, "auth_required", String(outcome.authRequired.length));
        for (const [index, entry] of outcome.authRequired.entries()) {
          // Credential codes are shown verbatim: an unknown future code displays rather than guesses.
          this.pair(dl, `auth_${String(index)}_credential`, String(entry.credential));
        }
        if (outcome.restore !== null) this.pair(dl, "restore_min_resource_fee_stroops", outcome.restore.minResourceFee);
        break;
      case "skipped":
      case "error":
      case "malformed":
        this.pair(dl, "reason", outcome.reason);
        break;
      case "timeout":
        this.pair(dl, "timeout_ms", String(outcome.timeoutMs));
        break;
      default:
        assertNever(outcome);
    }
    section.append(dl);
    return section;
  }
}

/** Fields an account effect adds beyond kind, operation and account. Exhaustive over the union. */
function accountEffectFields(e: AccountEffect): [string, string][] {
  switch (e.kind) {
    case "trustline":
      return [
        ["asset", e.asset],
        ["limit_stroops", e.limit.toString()],
      ];
    case "signer":
      return [
        ["signer", e.signer],
        ["signer_type", e.signerType],
        ["weight", String(e.weight)],
      ];
    case "thresholds": {
      const out: [string, string][] = [];
      if (e.masterWeight !== null) out.push(["master_weight", String(e.masterWeight)]);
      if (e.low !== null) out.push(["low_threshold", String(e.low)]);
      if (e.medium !== null) out.push(["medium_threshold", String(e.medium)]);
      if (e.high !== null) out.push(["high_threshold", String(e.high)]);
      return out;
    }
    case "flags": {
      const out: [string, string][] = [];
      if (e.set !== null) out.push(["flags_set", String(e.set)]);
      if (e.clear !== null) out.push(["flags_clear", String(e.clear)]);
      return out;
    }
    case "home_domain":
      // Raw bytes, decoded and sanitized as untrusted text at display time.
      return [["home_domain", sanitizeHexBytes(e.bytesHex)]];
    case "inflation_destination":
      return [["destination", e.destination]];
    case "merge":
      return [["destination", e.destination]];
    default:
      return assertNever(e);
  }
}
