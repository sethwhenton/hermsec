import {
  lstatSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  statSync,
} from "node:fs";
import path from "node:path";
import { gunzipSync } from "node:zlib";

const MAX_ARCHIVE_ENTRIES = 100_000;
const MAX_ARCHIVE_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_COMPRESSED_BYTES = 1024 * 1024 * 1024;

export function preflightArchive(archivePath, options = {}) {
  const entries = archivePath.toLowerCase().endsWith(".zip")
    ? inspectZipArchive(archivePath, options)
    : inspectTarGzipArchive(archivePath, options);
  validateArchiveEntries(entries, options);
  return entries;
}

export function inspectTarGzipArchive(archivePath, options = {}) {
  const limits = archiveLimits(options);
  const compressedSize = statSync(archivePath).size;
  if (!Number.isSafeInteger(compressedSize) || compressedSize > limits.maxCompressedBytes) {
    throw new Error("Runtime archive exceeds the compressed size limit.");
  }

  let archive;
  try {
    // `maxOutputLength` makes decompression fail before a gzip bomb can allocate
    // an unbounded payload. The compressed-size gate avoids reading an
    // arbitrarily large source file first.
    archive = gunzipSync(readFileSync(archivePath), { maxOutputLength: limits.maxUncompressedBytes });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (/maxOutputLength|buffer too large|larger than \d+ bytes|ERR_BUFFER_TOO_LARGE/iu.test(message)) {
      throw new Error("Runtime archive exceeds the uncompressed size limit.");
    }
    throw error;
  }
  const entries = [];
  let totalSize = 0;
  let offset = 0;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;

    const name = tarString(header.subarray(0, 100));
    const prefix = tarString(header.subarray(345, 500));
    const entryPath = prefix ? `${prefix}/${name}` : name;
    const linkTarget = tarString(header.subarray(157, 257));
    const size = parseTarSize(header.subarray(124, 136));
    const typeFlag = String.fromCharCode(header[156] || 48);
    entries.push({
      path: entryPath,
      type: tarEntryType(typeFlag),
      linkTarget: linkTarget || undefined,
      size,
    });
    totalSize = enforceInventoryBounds(entries, size, totalSize, limits);
    offset += 512 + Math.ceil(size / 512) * 512;
    if (offset > archive.length) {
      throw new Error(`Archive entry ${entryPath} extends beyond the tar payload.`);
    }
  }
  if (entries.length === 0) {
    throw new Error("Archive inventory is empty.");
  }
  return entries;
}

export function inspectZipArchive(archivePath, options = {}) {
  const limits = archiveLimits(options);
  const compressedSize = statSync(archivePath).size;
  if (!Number.isSafeInteger(compressedSize) || compressedSize > limits.maxCompressedBytes) {
    throw new Error("Runtime archive exceeds the compressed size limit.");
  }
  const archive = readFileSync(archivePath);
  const eocdOffset = findEndOfCentralDirectory(archive);
  const diskNumber = archive.readUInt16LE(eocdOffset + 4);
  const centralDisk = archive.readUInt16LE(eocdOffset + 6);
  const entryCount = archive.readUInt16LE(eocdOffset + 10);
  const centralSize = archive.readUInt32LE(eocdOffset + 12);
  const centralOffset = archive.readUInt32LE(eocdOffset + 16);
  if (
    diskNumber !== 0
    || centralDisk !== 0
    || entryCount === 0xffff
    || centralSize === 0xffffffff
    || centralOffset === 0xffffffff
  ) {
    throw new Error("Multi-disk and ZIP64 runtime archives are not supported.");
  }
  if (centralOffset + centralSize > archive.length) {
    throw new Error("ZIP central directory escapes the archive.");
  }

  const entries = [];
  let totalSize = 0;
  let offset = centralOffset;
  for (let index = 0; index < entryCount; index += 1) {
    if (offset + 46 > archive.length || archive.readUInt32LE(offset) !== 0x02014b50) {
      throw new Error("ZIP central directory entry is malformed.");
    }
    const flags = archive.readUInt16LE(offset + 8);
    if ((flags & 0x0001) !== 0) {
      throw new Error("Encrypted ZIP runtime entries are not supported.");
    }
    const compressionMethod = archive.readUInt16LE(offset + 10);
    const crc32 = archive.readUInt32LE(offset + 16);
    const compressedEntrySize = archive.readUInt32LE(offset + 20);
    const nameLength = archive.readUInt16LE(offset + 28);
    const extraLength = archive.readUInt16LE(offset + 30);
    const commentLength = archive.readUInt16LE(offset + 32);
    const uncompressedSize = archive.readUInt32LE(offset + 24);
    const externalAttributes = archive.readUInt32LE(offset + 38);
    const nameStart = offset + 46;
    const nameEnd = nameStart + nameLength;
    if (nameEnd + extraLength + commentLength > archive.length) {
      throw new Error("ZIP entry metadata extends beyond the archive.");
    }
    const encoding = (flags & 0x800) !== 0 ? "utf8" : "latin1";
    const nameBytes = archive.subarray(nameStart, nameEnd);
    const entryPath = nameBytes.toString(encoding);
    const localHeaderOffset = archive.readUInt32LE(offset + 42);
    assertMatchingZipLocalHeader(archive, {
      localHeaderOffset,
      flags,
      compressionMethod,
      crc32,
      compressedEntrySize,
      uncompressedSize,
      nameBytes,
      entryPath,
      centralOffset,
    });
    const unixMode = externalAttributes >>> 16;
    const unixType = unixMode & 0o170000;
    const type = entryPath.endsWith("/")
      ? "directory"
      : unixType === 0o120000
        ? "symlink"
        : unixType === 0o040000
          ? "directory"
          : unixType === 0 || unixType === 0o100000
            ? "file"
            : "special";
    entries.push({ path: entryPath, type, size: uncompressedSize });
    totalSize = enforceInventoryBounds(entries, uncompressedSize, totalSize, limits);
    offset = nameEnd + extraLength + commentLength;
  }
  if (offset > centralOffset + centralSize) {
    throw new Error("ZIP central directory inventory exceeds its declared size.");
  }
  return entries;
}

export function validateArchiveEntries(entries, options = {}) {
  const allowSafeSymlinks = options.allowSafeSymlinks === true;
  const caseInsensitivePaths = options.caseInsensitivePaths
    ?? (process.platform === "win32" || process.platform === "darwin");
  const seen = new Set();
  for (const entry of entries) {
    const normalized = normalizeArchivePath(entry.path);
    const key = caseInsensitivePaths ? normalized.toLowerCase() : normalized;
    if (seen.has(key)) {
      throw new Error(`Archive contains duplicate entry path ${entry.path}.`);
    }
    seen.add(key);

    if (entry.type === "hardlink") {
      throw new Error(`Archive hardlink entries are forbidden: ${entry.path}`);
    }
    if (entry.type === "symlink") {
      if (!allowSafeSymlinks) {
        throw new Error(`Archive symlink entries are forbidden: ${entry.path}`);
      }
      validateRelativeLinkTarget(normalized, entry.linkTarget);
      continue;
    }
    if (entry.type !== "file" && entry.type !== "directory") {
      throw new Error(`Archive contains unsupported ${entry.type} entry: ${entry.path}`);
    }
  }
}

export function verifyExtractedTree(rootPath, options = {}) {
  const root = realpathSync(path.resolve(rootPath));
  const allowSafeSymlinks = options.allowSafeSymlinks === true;
  const stack = [root];
  let entries = 0;
  while (stack.length > 0) {
    const directory = stack.pop();
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      entries += 1;
      if (entries > MAX_ARCHIVE_ENTRIES) {
        throw new Error("Extracted runtime tree exceeds the entry limit.");
      }
      const candidate = path.join(directory, entry.name);
      const metadata = lstatSync(candidate);
      if (metadata.isSymbolicLink()) {
        if (!allowSafeSymlinks) {
          throw new Error(`Extracted runtime contains forbidden symlink ${candidate}.`);
        }
        const target = readlinkSync(candidate);
        validateFilesystemLinkTarget(root, candidate, target);
        continue;
      }
      if (metadata.isDirectory()) {
        assertPathInside(root, realpathSync(candidate), "Extracted directory");
        stack.push(candidate);
        continue;
      }
      if (!metadata.isFile()) {
        throw new Error(`Extracted runtime contains unsupported filesystem entry ${candidate}.`);
      }
      if (metadata.nlink > 1) {
        throw new Error(`Extracted runtime contains hard-linked file ${candidate}.`);
      }
      assertPathInside(root, realpathSync(candidate), "Extracted file");
    }
  }
  return { root, entries };
}

function normalizeArchivePath(value) {
  const raw = String(value ?? "");
  if (!raw || /[\0-\x1f\x7f]/u.test(raw)) {
    throw new Error("Archive entry path is empty or contains control characters.");
  }
  const slashed = raw.replaceAll("\\", "/");
  if (slashed.startsWith("/") || slashed.startsWith("//") || /^[A-Za-z]:/u.test(slashed)) {
    throw new Error(`Archive entry uses an absolute path: ${raw}`);
  }
  const normalized = path.posix.normalize(slashed).replace(/\/+$/u, "");
  if (
    !normalized
    || normalized === "."
    || normalized === ".."
    || normalized.startsWith("../")
    || path.posix.isAbsolute(normalized)
  ) {
    throw new Error(`Archive entry escapes its extraction root: ${raw}`);
  }
  return normalized;
}

function validateRelativeLinkTarget(entryPath, targetValue) {
  const target = String(targetValue ?? "").replaceAll("\\", "/");
  if (!target || /[\0-\x1f\x7f]/u.test(target) || path.posix.isAbsolute(target) || /^[A-Za-z]:/u.test(target)) {
    throw new Error(`Archive symlink ${entryPath} has an unsafe target.`);
  }
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(entryPath), target));
  if (resolved === ".." || resolved.startsWith("../") || path.posix.isAbsolute(resolved)) {
    throw new Error(`Archive symlink ${entryPath} escapes the extraction root.`);
  }
}

function validateFilesystemLinkTarget(root, linkPath, target) {
  if (path.isAbsolute(target)) {
    throw new Error(`Extracted symlink uses an absolute target: ${linkPath}`);
  }
  const lexicalTarget = path.resolve(path.dirname(linkPath), target);
  assertPathInside(root, lexicalTarget, "Extracted symlink target");
  let realTarget;
  try {
    realTarget = realpathSync(lexicalTarget);
  } catch {
    throw new Error(`Extracted symlink target is missing or cyclic: ${linkPath}`);
  }
  assertPathInside(root, realTarget, "Extracted symlink target");
}

function assertPathInside(root, candidate, label) {
  const relative = path.relative(root, candidate);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`${label} escapes the runtime root: ${candidate}`);
  }
}

function tarEntryType(typeFlag) {
  if (typeFlag === "0" || typeFlag === "\0") return "file";
  if (typeFlag === "5") return "directory";
  if (typeFlag === "2") return "symlink";
  if (typeFlag === "1") return "hardlink";
  return "special";
}

function parseTarSize(bytes) {
  if ((bytes[0] & 0x80) !== 0) {
    throw new Error("Base-256 tar sizes are not supported for runtime archives.");
  }
  const value = tarString(bytes).trim();
  if (!/^[0-7]*$/u.test(value)) {
    throw new Error("Tar entry contains an invalid size.");
  }
  return Number.parseInt(value || "0", 8);
}

function tarString(bytes) {
  const nul = bytes.indexOf(0);
  return bytes.subarray(0, nul >= 0 ? nul : bytes.length).toString("utf8");
}

function enforceInventoryBounds(entries, nextSize, totalSize, limits) {
  if (entries.length > MAX_ARCHIVE_ENTRIES) {
    throw new Error("Runtime archive exceeds the entry limit.");
  }
  if (!Number.isSafeInteger(nextSize) || !Number.isSafeInteger(totalSize) || totalSize + nextSize > limits.maxUncompressedBytes) {
    throw new Error("Runtime archive exceeds the uncompressed size limit.");
  }
  return totalSize + nextSize;
}

function archiveLimits(options) {
  const maxCompressedBytes = options.maxCompressedBytes ?? MAX_ARCHIVE_COMPRESSED_BYTES;
  const maxUncompressedBytes = options.maxUncompressedBytes ?? MAX_ARCHIVE_UNCOMPRESSED_BYTES;
  if (!Number.isSafeInteger(maxCompressedBytes) || maxCompressedBytes <= 0) {
    throw new Error("Runtime archive compressed size limit is invalid.");
  }
  if (!Number.isSafeInteger(maxUncompressedBytes) || maxUncompressedBytes <= 0) {
    throw new Error("Runtime archive uncompressed size limit is invalid.");
  }
  return { maxCompressedBytes, maxUncompressedBytes };
}

function assertMatchingZipLocalHeader(archive, input) {
  const {
    localHeaderOffset,
    flags,
    compressionMethod,
    crc32,
    compressedEntrySize,
    uncompressedSize,
    nameBytes,
    entryPath,
    centralOffset,
  } = input;
  if (localHeaderOffset + 30 > archive.length || archive.readUInt32LE(localHeaderOffset) !== 0x04034b50) {
    throw new Error(`ZIP entry ${entryPath} has no valid local file header.`);
  }
  const localFlags = archive.readUInt16LE(localHeaderOffset + 6);
  const localCompressionMethod = archive.readUInt16LE(localHeaderOffset + 8);
  const localCrc32 = archive.readUInt32LE(localHeaderOffset + 14);
  const localCompressedSize = archive.readUInt32LE(localHeaderOffset + 18);
  const localUncompressedSize = archive.readUInt32LE(localHeaderOffset + 22);
  const localNameLength = archive.readUInt16LE(localHeaderOffset + 26);
  const localExtraLength = archive.readUInt16LE(localHeaderOffset + 28);
  const localNameStart = localHeaderOffset + 30;
  const localNameEnd = localNameStart + localNameLength;
  const dataEnd = localNameEnd + localExtraLength + compressedEntrySize;
  if (localNameEnd + localExtraLength > archive.length || dataEnd > centralOffset) {
    throw new Error(`ZIP local header for ${entryPath} extends beyond the archive.`);
  }
  const usesDataDescriptor = (flags & 0x0008) !== 0;
  const localSizesMatch = usesDataDescriptor
    ? [localCrc32, localCompressedSize, localUncompressedSize].every((value, index) =>
      value === 0 || value === [crc32, compressedEntrySize, uncompressedSize][index],
    )
    : localCrc32 === crc32
      && localCompressedSize === compressedEntrySize
      && localUncompressedSize === uncompressedSize;
  if (
    localFlags !== flags
    || localCompressionMethod !== compressionMethod
    || !localSizesMatch
    || !archive.subarray(localNameStart, localNameEnd).equals(nameBytes)
  ) {
    throw new Error(`ZIP central and local headers disagree for ${entryPath}.`);
  }
}

function findEndOfCentralDirectory(archive) {
  const minimum = Math.max(0, archive.length - 65_557);
  for (let offset = archive.length - 22; offset >= minimum; offset -= 1) {
    if (archive.readUInt32LE(offset) === 0x06054b50) return offset;
  }
  throw new Error("ZIP end-of-central-directory record was not found.");
}
