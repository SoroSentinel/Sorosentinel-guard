// Minimal usage sample: put Guard in front of a SEP-43-style wallet, on either
// signing path, and print what happens. See README.md next to this file.
//
//   node examples/wallet-adapter/sign.mts --path transaction --approve
//
// The wallet below is a stub: it holds no key and produces no signature, and it
// returns the bytes it was shown (or, with --tamper, different bytes) so the
// two outcomes of the byte-fidelity check are both visible offline. A real
// wallet replaces this one object; Guard's calls do not change.
//
// Raw XDR is never printed: only lengths, codes, facts and statuses.
import { readFileSync } from "node:fs";

import {
  guardSignAuthEntry,
  guardSignTransaction,
  type GuardedSignAuthEntry,
  type GuardedSignTransaction,
  type Sep43Signer,
} from "../../packages/adapter-reference/src/index.ts";
import { sanitizeUntrusted } from "../../packages/core/src/index.ts";
import type { AnalysisStatus, AuthEntryAddress, Finding } from "../../packages/core/src/index.ts";

interface Fixture {
  name: string;
  network_passphrase: string;
  xdr: string;
  expected: { source?: string };
}

const SETS = {
  transaction: {
    analyzed: "../../fixtures/tx/benign/payment_native.json",
    other: "../../fixtures/tx/benign/create_account.json",
  },
  auth_entry: {
    analyzed: "../../fixtures/auth_entry/benign/credential_address.json",
    other: "../../fixtures/auth_entry/benign/address_is_contract.json",
  },
} as const;

interface Args {
  path: keyof typeof SETS;
  approve: boolean;
  tamper: boolean;
  signature: boolean;
}

function usage(message: string): never {
  console.error(message);
  console.error("usage: node examples/wallet-adapter/sign.mts [--path transaction|auth_entry] [--approve] [--tamper] [--signature]");
  process.exit(2);
}

function parseArgs(argv: readonly string[]): Args {
  const args: Args = { path: "transaction", approve: false, tamper: false, signature: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--approve") args.approve = true;
    else if (flag === "--tamper") args.tamper = true;
    else if (flag === "--signature") args.signature = true;
    else if (flag === "--path") {
      const value = argv[++i];
      if (value !== "transaction" && value !== "auth_entry") usage(`--path needs transaction or auth_entry, got ${value ?? ""}`);
      args.path = value;
    } else usage(`unknown argument ${flag}`);
  }
  if (args.signature && args.path !== "auth_entry") usage("--signature answers signAuthEntry, so pass --path auth_entry too");
  return args;
}

function load(path: string): Fixture {
  return JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8")) as Fixture;
}

/** The parts both analyses carry, so one printer covers both signing paths. */
interface Printable {
  status: AnalysisStatus;
  findings: readonly Finding[];
  notChecked: readonly string[];
  address?: AuthEntryAddress | null;
}

function printAnalysis(analysis: Printable): void {
  console.log(`analysis: status=${analysis.status} findings=${analysis.findings.length} not_checked=${analysis.notChecked.join(", ") || "none"}`);
  for (const f of analysis.findings) {
    const op = f.operationIndex === null ? "" : ` op=${f.operationIndex}`;
    const facts = Object.entries(f.facts).map(([k, v]) => `${k}=${sanitizeUntrusted(v)}`).join(" ");
    console.log(`  ${f.severity} ${f.code}${op}${facts === "" ? "" : ` ${facts}`}`);
  }
  if (analysis.address) console.log(`  credential address: ${JSON.stringify(analysis.address)}`);
}

function printOutcome(r: GuardedSignTransaction | GuardedSignAuthEntry): void {
  if (r.outcome === "signed") {
    console.log(`outcome: signed, and the bytes match what was analyzed (status=${r.status})`);
    return;
  }
  if (r.outcome === "signed_other_bytes") {
    console.log("outcome: the wallet signed, but not the analyzed bytes, so the analysis above does not describe them (status=partial)");
    return;
  }
  if (r.outcome === "signed_preimage_verified") {
    console.log(`outcome: the wallet's bare signature authorizes exactly the entry analyzed above (status=${r.status})`);
    return;
  }
  if (r.outcome === "signed_preimage_mismatch") {
    console.log("outcome: the wallet signed, but not the analyzed entry's authorization payload, so the analysis above does not describe what it signed (status=partial)");
    return;
  }
  if (r.outcome === "signed_unverifiable") {
    console.log(`outcome: the wallet's reply carries nothing that could be related to the analyzed entry (reason=${r.reason}, status=partial)`);
    return;
  }
  // Only a wallet's own text reaches the console, and only sanitized: reason
  // codes are Guard's, wording is the integrator's renderer's job.
  const said = r.walletError === null ? "" : ` wallet_said(code=${r.walletError.code})="${sanitizeUntrusted(r.walletError.message)}"`;
  console.log(`outcome: not_signed reason=${r.reason} (status=${r.status})${said}`);
}

const args = parseArgs(process.argv.slice(2));
const analyzed = load(SETS[args.path].analyzed);
const other = load(SETS[args.path].other);
const signerAddress = analyzed.expected.source ?? null;

/**
 * The stub wallet: no key, no network, no submission. A real wallet gets the
 * same `opts`, including the `networkPassphrase` the adapter copies from the
 * analysis context; this stub needs neither, and logs no value from the request
 * beyond its size.
 */
const wallet: Sep43Signer = {
  async signTransaction(xdrBase64) {
    console.log(`wallet: signTransaction asked for ${xdrBase64.length} base64 chars`);
    return { signedTxXdr: args.tamper ? other.xdr : xdrBase64, ...(signerAddress === null ? {} : { signerAddress }) };
  },
  async signAuthEntry(authEntryBase64) {
    console.log(`wallet: signAuthEntry asked for ${authEntryBase64.length} base64 chars`);
    // --signature is Freighter's reading of SEP-43: it was handed the entry's
    // preimage, so it answers with the signature alone and the dApp assembles
    // the entry. Guard can still check those 64 bytes against the payload the
    // analyzed entry implies; these ones are not it, and the stub signs nothing.
    if (args.signature) {
      const signatureOnly = btoa(String.fromCharCode(...new Uint8Array(64).fill(8)));
      return { signedAuthEntry: signatureOnly, ...(signerAddress === null ? {} : { signerAddress }) };
    }
    return { signedAuthEntry: args.tamper ? other.xdr : authEntryBase64, ...(signerAddress === null ? {} : { signerAddress }) };
  },
};

const review = (analysis: Printable) => {
  printAnalysis(analysis);
  console.log(`review: ${args.approve ? "approving" : "declining"} (--approve to let the wallet be asked)`);
  return args.approve;
};

const result =
  args.path === "transaction"
    ? await guardSignTransaction(wallet, analyzed.xdr, { networkPassphrase: analyzed.network_passphrase }, (a) => review(a))
    : await guardSignAuthEntry(wallet, analyzed.xdr, { networkPassphrase: analyzed.network_passphrase }, (a) => review(a));

printOutcome(result);
// 0 only when what was analyzed is what was authorized: the same bytes, or a
// bare signature checked against the payload those bytes imply.
process.exitCode = result.outcome === "signed" || result.outcome === "signed_preimage_verified" ? 0 : 1;
