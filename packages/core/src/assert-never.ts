/** Compile-time exhaustiveness check; throws if reached at runtime. */
export function assertNever(x: never): never {
  throw new Error(`unhandled variant: ${String((x as { type?: unknown } | null)?.type ?? x)}`);
}
