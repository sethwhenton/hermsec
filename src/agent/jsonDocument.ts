export function parseSingleJsonObject(
  content: string,
): Record<string, unknown> | undefined {
  const document = singleJsonDocument(content);
  if (document === undefined) {
    return undefined;
  }
  try {
    const value = JSON.parse(document) as unknown;
    return isPlainRecord(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function singleJsonDocument(content: string): string | undefined {
  const trimmed = content.trim();
  if (!trimmed) {
    return undefined;
  }
  if (!trimmed.startsWith("```")) {
    return trimmed;
  }
  const match =
    /^```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n```[ \t]*$/iu.exec(
      trimmed,
    );
  return match?.[1]?.trim();
}

function isPlainRecord(
  value: unknown,
): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
