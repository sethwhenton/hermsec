export function isLoopbackProviderUrl(value: string | undefined): boolean {
  if (!value?.trim()) return false;
  try {
    const hostname = new URL(value).hostname
      .toLocaleLowerCase()
      .replace(/^\[|\]$/gu, "");
    return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
  } catch {
    return false;
  }
}
