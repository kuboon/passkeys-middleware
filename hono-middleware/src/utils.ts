export const cryptoRandomUUIDFallback = (): string => {
  const bytes = new Uint8Array(16);
  const cryptoObj: Crypto | undefined = typeof globalThis.crypto !== "undefined"
    ? globalThis.crypto
    : undefined;
  if (cryptoObj?.getRandomValues) {
    cryptoObj.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${
    hex.slice(6, 8).join("")
  }-${hex.slice(8, 10).join("")}-${hex.slice(10, 16).join("")}`;
};

const readTextFile = async (path: string): Promise<string> => {
  if (typeof Deno !== "undefined" && typeof Deno.readTextFile === "function") {
    return Deno.readTextFile(path);
  }
  try {
    const { readFile } = await import("node:fs/promises");
    return readFile(path, "utf8");
  } catch (error) {
    throw new Error(
      `Unable to read file '${path}': ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
};

export const loadSimpleWebAuthnClient = async (): Promise<string> => {
  const moduleUrl =
    "https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js";
  if (moduleUrl.startsWith("file://")) {
    return readTextFile(moduleUrl.slice("file://".length));
  }
  if (moduleUrl.startsWith("http://") || moduleUrl.startsWith("https://")) {
    const response = await fetch(moduleUrl);
    if (!response.ok) {
      throw new Error(
        `Failed to fetch SimpleWebAuthn client bundle: ${response.statusText}`,
      );
    }
    return response.text();
  }
  return readTextFile(moduleUrl);
};
