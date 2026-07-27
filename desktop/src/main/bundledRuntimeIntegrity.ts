import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { rm as rmAsync } from "node:fs/promises";
import path from "node:path";

export type BundledResourceEntry = {
  path: string;
  kind: "directory" | "file" | "symlink";
  size: number;
  sha256: string;
};

export type BundledResourceIntegrityAnchor = {
  schemaVersion: "1.0";
  platform: string;
  arch: string;
  roots: string[];
  files: BundledResourceEntry[];
  treeSha256: string;
};

export type BundledResourceVerification = {
  resourcesRoot: string;
  cliRoot: string;
  toolsRoot: string;
  anchor: BundledResourceIntegrityAnchor;
};

export type VerifiedBundleExecutionLease = BundledResourceVerification & {
  leaseRoot: string;
  cliEntryPath: string;
  assertIntact: () => void;
  release: () => Promise<void>;
};

const CLI_ENTRY_PATH = path.posix.join("hermsec-cli", "dist", "src", "bin", "hermsec.js");

/**
 * This inventory intentionally includes the runtime manifest itself. The manifest
 * remains useful runtime metadata, but it is never the trust anchor.
 */
export function createBundledResourceIntegrityAnchor(input: {
  resourcesRoot: string;
  platform: string;
  arch: string;
}): BundledResourceIntegrityAnchor {
  const roots = bundledResourceRoots(input.platform, input.arch);
  const files = buildBundledResourceInventory(path.resolve(input.resourcesRoot), roots);
  return {
    schemaVersion: "1.0",
    platform: input.platform,
    arch: input.arch,
    roots,
    files,
    treeSha256: digestEntries(files),
  };
}

export function verifyBundledResourceIntegrity(input: {
  resourcesRoot: string;
  anchor: BundledResourceIntegrityAnchor;
  platform?: string;
  arch?: string;
}): BundledResourceVerification {
  const resourcesRoot = path.resolve(input.resourcesRoot);
  const platform = input.platform ?? process.platform;
  const arch = input.arch ?? process.arch;
  const anchor = validateAnchor(input.anchor, platform, arch);
  const actual = buildBundledResourceInventory(resourcesRoot, anchor.roots);
  if (JSON.stringify(actual) !== JSON.stringify(anchor.files)) {
    throw new Error("Bundled resource inventory does not match the immutable build integrity anchor.");
  }
  if (digestEntries(actual) !== anchor.treeSha256) {
    throw new Error("Bundled resource tree hash does not match the immutable build integrity anchor.");
  }

  const cliRoot = resolveAnchoredPath(resourcesRoot, "hermsec-cli");
  const toolsRoot = resolveAnchoredPath(resourcesRoot, `runtime-tools/${platform}-${arch}`);
  const cliEntry = resolveAnchoredPath(resourcesRoot, CLI_ENTRY_PATH);
  if (!lstatSync(cliEntry).isFile()) {
    throw new Error("Bundled Hermsec CLI entrypoint is missing from the integrity-verified bundle.");
  }
  return { resourcesRoot, cliRoot, toolsRoot, anchor };
}

/**
 * Materializes a per-operation immutable snapshot. Every copied byte is checked
 * against the embedded anchor, so source-tree swaps during copying fail closed.
 * It protects the mutable external resource directory from post-install changes.
 * A same-user attacker able to rewrite Electron's main bundle or this process's
 * private temporary directory is outside this unsigned-build boundary; release
 * code signing and OS ACLs remain the protection for that stronger attacker.
 */
export function createVerifiedBundleExecutionLease(input: {
  resourcesRoot: string;
  leaseParent: string;
  anchor: BundledResourceIntegrityAnchor;
  platform?: string;
  arch?: string;
}): VerifiedBundleExecutionLease {
  const source = verifyBundledResourceIntegrity({
    resourcesRoot: input.resourcesRoot,
    anchor: input.anchor,
    platform: input.platform,
    arch: input.arch,
  });
  mkdirSync(input.leaseParent, { recursive: true });
  const leaseRoot = mkdtempSync(path.join(path.resolve(input.leaseParent), "hermsec-runtime-lease-"));
  try {
    materializeVerifiedSnapshot(source.resourcesRoot, leaseRoot, source.anchor.files);
    const snapshot = verifyBundledResourceIntegrity({
      resourcesRoot: leaseRoot,
      anchor: source.anchor,
      platform: input.platform,
      arch: input.arch,
    });
    hardenSnapshotPermissions(leaseRoot, source.anchor.files);
    let released = false;
    let releasePromise: Promise<void> | undefined;
    return {
      ...snapshot,
      leaseRoot,
      cliEntryPath: resolveAnchoredPath(leaseRoot, CLI_ENTRY_PATH),
      assertIntact: () => {
        if (released) throw new Error("Bundled runtime execution lease has already been released.");
        verifyBundledResourceIntegrity({
          resourcesRoot: leaseRoot,
          anchor: source.anchor,
          platform: input.platform,
          arch: input.arch,
        });
      },
      release: () => {
        if (releasePromise) return releasePromise;
        released = true;
        releasePromise = removeLeaseSnapshot(leaseRoot, source.anchor.files);
        return releasePromise;
      },
    };
  } catch (error) {
    removeLeaseSnapshotSync(leaseRoot, source.anchor.files);
    throw error;
  }
}

export function bundledResourceRoots(platform: string = process.platform, arch: string = process.arch): string[] {
  return ["hermsec-cli", `runtime-tools/${platform}-${arch}`];
}

export function buildBundledResourceInventory(
  resourcesRoot: string,
  roots: readonly string[],
): BundledResourceEntry[] {
  const root = path.resolve(resourcesRoot);
  const entries: BundledResourceEntry[] = [];
  for (const relativeRoot of [...roots].sort(compareText)) {
    if (!isCanonicalPath(relativeRoot)) {
      throw new Error(`Bundled integrity root is unsafe: ${relativeRoot}`);
    }
    const start = resolveAnchoredPath(root, relativeRoot);
    if (!existsSync(start) || !lstatSync(start).isDirectory()) {
      throw new Error(`Bundled integrity root is missing or is not a directory: ${relativeRoot}`);
    }
    const stack = [start];
    while (stack.length > 0) {
      const current = stack.pop() as string;
      const relativePath = toRelativePath(root, current);
      const stat = lstatSync(current);
      if (stat.isDirectory()) {
        entries.push({ path: relativePath, kind: "directory", size: 0, sha256: digestBuffer(Buffer.alloc(0)) });
        const children = readdirSync(current, { withFileTypes: true })
          .sort((left, right) => compareText(left.name, right.name));
        for (let index = children.length - 1; index >= 0; index -= 1) {
          stack.push(path.join(current, children[index]!.name));
        }
        continue;
      }
      if (stat.isSymbolicLink()) {
        const target = readlinkSync(current);
        assertConfinedRelativeLink(root, current, target);
        const bytes = Buffer.from(target, "utf8");
        entries.push({ path: relativePath, kind: "symlink", size: bytes.byteLength, sha256: digestBuffer(bytes) });
        continue;
      }
      if (!stat.isFile()) {
        throw new Error(`Bundled resource tree contains an unsupported entry: ${relativePath}`);
      }
      entries.push({
        path: relativePath,
        kind: "file",
        size: stat.size,
        sha256: digestBuffer(readFileSync(current)),
      });
    }
  }
  return entries.sort((left, right) => compareText(left.path, right.path));
}

function materializeVerifiedSnapshot(
  sourceRoot: string,
  leaseRoot: string,
  entries: readonly BundledResourceEntry[],
): void {
  for (const entry of entries) {
    const source = resolveAnchoredPath(sourceRoot, entry.path);
    const destination = resolveAnchoredPath(leaseRoot, entry.path);
    if (entry.kind === "directory") {
      assertEntryMatches(source, entry);
      mkdirSync(destination, { recursive: true });
      continue;
    }
    mkdirSync(path.dirname(destination), { recursive: true });
    if (entry.kind === "symlink") {
      assertEntryMatches(source, entry);
      if (process.platform === "win32") {
        throw new Error("Windows bundled execution leases do not permit symbolic links.");
      }
      symlinkSync(readlinkSync(source), destination);
      assertEntryMatches(destination, entry);
      continue;
    }
    assertEntryMatches(source, entry);
    copyFileSync(source, destination);
    assertEntryMatches(destination, entry);
  }
}

function hardenSnapshotPermissions(leaseRoot: string, entries: readonly BundledResourceEntry[]): void {
  for (const entry of [...entries].sort((left, right) => right.path.length - left.path.length)) {
    const target = resolveAnchoredPath(leaseRoot, entry.path);
    try {
      if (entry.kind === "directory") {
        chmodSync(target, 0o555);
      } else if (entry.kind === "file") {
        chmodSync(target, isExecutableEntry(entry.path) ? 0o555 : 0o444);
      }
    } catch {
      // Some Windows filesystems expose only a readonly attribute. The content
      // verification before every spawn remains the security boundary.
    }
  }
}

function prepareLeaseSnapshotForRemoval(
  leaseRoot: string,
  entries: readonly BundledResourceEntry[],
): void {
  try {
    if (lstatSync(leaseRoot).isDirectory()) {
      chmodSync(leaseRoot, 0o700);
    }
  } catch {
    // Recursive removal below remains the final cleanup attempt.
  }
  for (const entry of entries) {
    if (entry.kind === "symlink") continue;
    const target = resolveAnchoredPath(leaseRoot, entry.path);
    try {
      const stat = lstatSync(target);
      if (stat.isDirectory()) {
        chmodSync(target, 0o700);
      } else if (process.platform === "win32" && stat.isFile()) {
        chmodSync(target, 0o600);
      }
    } catch {
      // A missing entry is handled by the confined recursive removal.
    }
  }
}

async function removeLeaseSnapshot(
  leaseRoot: string,
  entries: readonly BundledResourceEntry[],
): Promise<void> {
  prepareLeaseSnapshotForRemoval(leaseRoot, entries);
  try {
    await rmAsync(leaseRoot, {
      recursive: true,
      force: true,
      maxRetries: 10,
      retryDelay: 100,
    });
  } catch (error) {
    hardenSnapshotPermissions(leaseRoot, entries);
    throw error;
  }
}

function removeLeaseSnapshotSync(
  leaseRoot: string,
  entries: readonly BundledResourceEntry[],
): void {
  prepareLeaseSnapshotForRemoval(leaseRoot, entries);
  try {
    rmSync(leaseRoot, { recursive: true, force: true, maxRetries: 3, retryDelay: 40 });
  } catch (error) {
    hardenSnapshotPermissions(leaseRoot, entries);
    throw error;
  }
}

function isExecutableEntry(relativePath: string): boolean {
  return relativePath.includes("/bin/") || relativePath.endsWith("/python-runtime/python.exe");
}

function assertEntryMatches(filePath: string, expected: BundledResourceEntry): void {
  if (!existsSync(filePath)) {
    throw new Error(`Bundled resource changed while creating execution lease: ${expected.path}`);
  }
  const stat = lstatSync(filePath);
  const kind = stat.isDirectory() ? "directory" : stat.isSymbolicLink() ? "symlink" : stat.isFile() ? "file" : undefined;
  if (kind !== expected.kind) {
    throw new Error(`Bundled resource type changed while creating execution lease: ${expected.path}`);
  }
  if (kind === "directory") return;
  if (kind === "symlink") {
    const target = readlinkSync(filePath);
    const bytes = Buffer.from(target, "utf8");
    if (bytes.byteLength !== expected.size || digestBuffer(bytes) !== expected.sha256) {
      throw new Error(`Bundled symbolic link changed while creating execution lease: ${expected.path}`);
    }
    return;
  }
  if (stat.size !== expected.size || digestBuffer(readFileSync(filePath)) !== expected.sha256) {
    throw new Error(`Bundled resource bytes changed while creating execution lease: ${expected.path}`);
  }
}

function validateAnchor(
  value: BundledResourceIntegrityAnchor,
  platform: string,
  arch: string,
): BundledResourceIntegrityAnchor {
  if (
    !value
    || value.schemaVersion !== "1.0"
    || value.platform !== platform
    || value.arch !== arch
    || !Array.isArray(value.roots)
    || !Array.isArray(value.files)
    || !/^[a-f0-9]{64}$/u.test(value.treeSha256 ?? "")
  ) {
    throw new Error("Bundled resource integrity anchor is missing, malformed, or for a different platform.");
  }
  const expectedRoots = bundledResourceRoots(platform, arch);
  if (JSON.stringify([...value.roots].sort(compareText)) !== JSON.stringify(expectedRoots)) {
    throw new Error("Bundled resource integrity anchor has unexpected resource roots.");
  }
  const seen = new Set<string>();
  const files = [...value.files].sort((left, right) => compareText(left.path, right.path));
  for (const entry of files) {
    if (
      !entry
      || !isCanonicalPath(entry.path)
      || seen.has(entry.path)
      || (entry.kind !== "directory" && entry.kind !== "file" && entry.kind !== "symlink")
      || !Number.isSafeInteger(entry.size)
      || entry.size < 0
      || !/^[a-f0-9]{64}$/u.test(entry.sha256 ?? "")
      || !value.roots.some((root) => entry.path === root || entry.path.startsWith(`${root}/`))
    ) {
      throw new Error("Bundled resource integrity anchor has an unsafe inventory entry.");
    }
    seen.add(entry.path);
  }
  if (digestEntries(files) !== value.treeSha256) {
    throw new Error("Bundled resource integrity anchor has an invalid tree hash.");
  }
  return { ...value, roots: [...value.roots].sort(compareText), files };
}

function resolveAnchoredPath(root: string, relativePath: string): string {
  if (!isCanonicalPath(relativePath)) throw new Error(`Unsafe bundled resource path: ${relativePath}`);
  const target = path.resolve(root, relativePath);
  const relative = path.relative(root, target);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`Bundled resource path escapes its root: ${relativePath}`);
  }
  return target;
}

function toRelativePath(root: string, filePath: string): string {
  const value = path.relative(root, filePath).replaceAll("\\", "/");
  if (!isCanonicalPath(value)) throw new Error(`Bundled resource tree contains an unsafe path: ${value}`);
  return value;
}

function isCanonicalPath(value: string): boolean {
  return Boolean(
    value
    && !value.includes("\\")
    && !value.includes("\0")
    && !path.posix.isAbsolute(value)
    && path.posix.normalize(value) === value
    && value !== "."
    && !value.startsWith("../"),
  );
}

function assertConfinedRelativeLink(root: string, linkPath: string, target: string): void {
  if (path.isAbsolute(target)) {
    throw new Error(`Bundled resource tree contains an absolute symbolic link: ${linkPath}`);
  }
  const resolved = path.resolve(path.dirname(linkPath), target);
  const relative = path.relative(root, resolved);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`Bundled resource symbolic link escapes the bundle: ${linkPath}`);
  }
}

function digestEntries(entries: readonly BundledResourceEntry[]): string {
  return digestBuffer(Buffer.from(JSON.stringify(entries), "utf8"));
}

function digestBuffer(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
