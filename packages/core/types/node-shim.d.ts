// Minimal declarations for the few Node built-ins used by tests and scripts,
// instead of adding @types/node as a dependency. src/ must not use these:
// the SDK runs in browsers and wallets too.
declare module "node:fs" {
  export function readFileSync(path: string | URL, encoding: "utf8"): string;
  export function readdirSync(path: string | URL): string[];
  export function writeFileSync(path: string | URL, data: string): void;
  export function mkdirSync(path: string | URL, options: { recursive: true }): void;
}
