// Minimal declarations for the few Node built-ins used by tests and scripts,
// instead of adding @types/node as a dependency. src/ must not use these:
// the SDK runs in browsers and wallets too.
declare module "node:fs" {
  export function readFileSync(path: string | URL, encoding: "utf8"): string;
  export function readdirSync(path: string | URL): string[];
  export function writeFileSync(path: string | URL, data: string): void;
  export function mkdirSync(path: string | URL, options: { recursive: true }): void;
  export function mkdtempSync(prefix: string): string;
}

declare module "node:os" {
  export function tmpdir(): string;
  export function platform(): string;
  export function arch(): string;
  export function cpus(): readonly { model: string }[];
}

declare module "node:child_process" {
  export function spawnSync(
    command: string,
    args: readonly string[],
    options: { encoding: "utf8" },
  ): { status: number | null; stdout: string; stderr: string };
}

declare const process: {
  readonly argv: string[];
  readonly execPath: string;
  readonly version: string;
  readonly env: Readonly<Record<string, string | undefined>>;
  exitCode: number | undefined;
  exit(code: number): never;
};
