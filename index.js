#!/usr/bin/env node
"use strict";

/**
 * mcp-tmpfs-server
 *
 * A dependency-free MCP server (speaks MCP over stdio, JSON-RPC 2.0) that
 * exposes list/read/write/delete file tools scoped to a single sandbox
 * directory (a temp dir by default). No third-party packages required.
 */

const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline");
const zlib = require("node:zlib");
const { promisify } = require("node:util");

const gunzip = promisify(zlib.gunzip);
const inflate = promisify(zlib.inflate);

// ---- configuration -------------------------------------------------------

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB limit
const OPERATION_TIMEOUT = 10000; // 10 second timeout
const MAX_RECURSION_DEPTH = 64; // Prevent deep/ circular directory traversal

// Allow following symlinks (default: false for security)
// Set MCP_TMPFS_ALLOW_SYMLINKS=true or MCP_TMPFS_ALLOW_SYMLINKS=1 to enable
const ALLOW_SYMLINKS = 
  process.env.MCP_TMPFS_ALLOW_SYMLINKS === "true" ||
  process.env.MCP_TMPFS_ALLOW_SYMLINKS === "1";

// ---- sandbox root -----------------------------------------------------

const argDir = process.argv
  .find((a) => a.startsWith("--dir="))
  ?.slice("--dir=".length);

const ROOT_DIR = path.resolve(
  argDir || process.env.MCP_TMPFS_DIR || path.join(os.tmpdir(), "mcp-tmpfs-server")
);

// ---- security utilities -------------------------------------------------

/**
 * Validates that a path is safe (not null bytes, not escaping ROOT_DIR).
 * When ALLOW_SYMLINKS is false (default), uses realpath to resolve symlinks
 * and prevent bypass. When ALLOW_SYMLINKS is true, skips symlink resolution.
 * For non-existent paths, falls back to path string validation.
 */
async function resolveSafe(relativePath) {
  if (typeof relativePath !== "string") {
    throw new Error("Path must be a string");
  }
  if (relativePath.includes("\0")) {
    throw new Error("Null bytes not allowed in path");
  }
  
  const target = path.resolve(ROOT_DIR, relativePath || ".");
  
  let realTarget = target;
  
  // Only resolve symlinks if ALLOW_SYMLINKS is false (secure by default)
  if (!ALLOW_SYMLINKS) {
    // Try to resolve symlinks. For non-existent paths, this will fail with ENOENT.
    // In that case, we fall back to checking the path string.
    // This means we can't catch symlink escapes for non-existent paths,
    // but we CAN catch them for existing paths (which is the main threat).
    try {
      realTarget = await fs.realpath(target);
    } catch (err) {
      if (err.code === "ENOENT") {
        // Path doesn't exist yet (e.g., for write_file creating new file)
        // Fall back to the resolved path without symlink resolution
        realTarget = target;
      } else {
        throw err;
      }
    }
  }
  
  // Check that the resolved path is still within ROOT_DIR
  const rel = path.relative(ROOT_DIR, realTarget);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new Error(`Path escapes the allowed directory: ${relativePath}`);
  }
  
  return realTarget;
}

/**
 * Recursively lists files, with cycle detection.
 * When ALLOW_SYMLINKS is false, uses realpath to detect symlink cycles.
 * When ALLOW_SYMLINKS is true, uses path resolution to detect path cycles.
 */
async function listFilesRecursive(dir, base = dir, visited = new Set(), depth = 0) {
  if (depth > MAX_RECURSION_DEPTH) {
    throw new Error("Maximum recursion depth exceeded");
  }
  
  let realDir = dir;
  
  // Only resolve symlinks if ALLOW_SYMLINKS is false
  if (!ALLOW_SYMLINKS) {
    try {
      realDir = await fs.realpath(dir);
    } catch (err) {
      if (err.code === "ENOENT") {
        // Directory doesn't exist or was deleted during traversal
        return [];
      }
      throw err;
    }
  }
  
  if (visited.has(realDir)) {
    // Already visited this directory (cycle detected)
    return [];
  }
  visited.add(realDir);
  
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch (err) {
    if (err.code === "ENOTDIR" || err.code === "ENOENT") {
      // Not a directory or doesn't exist (could be a symlink to a file)
      return [];
    }
    throw err;
  }
  
  let results = [];
  
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    
    let realFull = full;
    
    // Only resolve symlinks if ALLOW_SYMLINKS is false
    if (!ALLOW_SYMLINKS) {
      try {
        realFull = await fs.realpath(full);
      } catch (err) {
        if (err.code === "ENOENT") {
          // Entry doesn't exist (race condition: deleted during traversal)
          continue;
        }
        throw err;
      }
    }
    
    const rel = path.relative(base, realFull);
    
    if (entry.isDirectory()) {
      results.push({ path: rel, type: "directory" });
      results = results.concat(
        await listFilesRecursive(full, base, new Set(visited), depth + 1)
      );
    } else {
      let stat;
      try {
        stat = await fs.stat(realFull);
      } catch (err) {
        if (err.code === "ENOENT") {
          // File doesn't exist (race condition)
          continue;
        }
        throw err;
      }
      results.push({ path: rel, type: "file", size: stat.size });
    }
  }
  
  return results;
}

/**
 * Wrapper to add timeout to async operations.
 */
async function withTimeout(promise, ms) {
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => reject(new Error(`Operation timed out after ${ms}ms`)), ms);
  });
  return await Promise.race([promise, timeoutPromise]);
}

// ---- ZIP file parsing utilities ---------------------------------------------

/**
 * ZIP file constants
 */
const ZIP_LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
const ZIP_CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const ZIP_END_OF_CD_SIGNATURE = 0x06054b50;
const ZIP64_END_OF_CD_SIGNATURE = 0x06064b50;
const ZIP64_END_OF_CD_LOCATOR_SIGNATURE = 0x07064b50;

/**
 * ZIP compression method constants
 */
const ZIP_COMPRESSION_STORED = 0;
const ZIP_COMPRESSION_DEFLATED = 8;

/**
 * Read a 4-byte little-endian unsigned integer from a buffer
 */
function readUInt32LE(buf, offset) {
  return buf.readUInt32LE(offset);
}

/**
 * Read a 2-byte little-endian unsigned integer from a buffer
 */
function readUInt16LE(buf, offset) {
  return buf.readUInt16LE(offset);
}

/**
 * Decompress data based on compression method
 */
async function decompressData(data, compressionMethod) {
  if (compressionMethod === ZIP_COMPRESSION_STORED) {
    // No compression
    return data;
  } else if (compressionMethod === ZIP_COMPRESSION_DEFLATED) {
    // Try inflate first (more common for ZIP), then gunzip
    try {
      return await inflate(data);
    } catch (e) {
      try {
        return await gunzip(data);
      } catch (e2) {
        throw new Error(`Failed to decompress: ${e2.message}`);
      }
    }
  } else {
    throw new Error(`Unsupported compression method: ${compressionMethod}`);
  }
}

/**
 * Find the End of Central Directory record in a ZIP file
 * Returns the offset of the EOCD record
 */
function findEndOfCentralDirectory(buf) {
  // ZIP comment can be up to 64KB, so search from the end
  const minEOCDSize = 22; // Minimum EOCD size without comment
  const maxCommentLength = 65535;
  const searchStart = Math.max(0, buf.length - minEOCDSize - maxCommentLength);
  
  // Search backwards for the EOCD signature
  for (let i = buf.length - 4; i >= searchStart; i--) {
    const signature = buf.readUInt32LE(i);
    
    // Check for ZIP64 EOCD locator first (if present, actual EOCD is before it)
    if (signature === ZIP64_END_OF_CD_LOCATOR_SIGNATURE) {
      // Skip this and continue searching
      continue;
    }
    
    if (signature === ZIP_END_OF_CD_SIGNATURE) {
      return i;
    }
    
    // Also check for ZIP64 EOCD
    if (signature === ZIP64_END_OF_CD_SIGNATURE) {
      // For simplicity, we'll skip ZIP64 support for now
      // and treat it as a regular EOCD
      return i;
    }
  }
  
  throw new Error("End of Central Directory record not found");
}

/**
 * Parse the End of Central Directory record
 */
function parseEndOfCentralDirectory(buf, offset) {
  if (buf.readUInt32LE(offset) !== ZIP_END_OF_CD_SIGNATURE) {
    throw new Error("Invalid EOCD signature");
  }
  
  const diskNumber = readUInt16LE(buf, offset + 4);
  const cdDiskNumber = readUInt16LE(buf, offset + 6);
  const cdRecordsOnDisk = readUInt16LE(buf, offset + 8);
  const totalCdRecords = readUInt16LE(buf, offset + 10);
  const cdSize = readUInt32LE(buf, offset + 12);
  const cdOffset = readUInt32LE(buf, offset + 16);
  const commentLength = readUInt16LE(buf, offset + 20);
  
  return {
    diskNumber,
    cdDiskNumber,
    cdRecordsOnDisk,
    totalCdRecords,
    cdSize,
    cdOffset,
    commentLength,
    comment: commentLength > 0 ? buf.subarray(offset + 22, offset + 22 + commentLength).toString("utf8") : "",
  };
}

/**
 * Parse a Central Directory file header
 */
function parseCentralDirectoryEntry(buf, offset) {
  if (buf.readUInt32LE(offset) !== ZIP_CENTRAL_DIRECTORY_SIGNATURE) {
    throw new Error("Invalid Central Directory signature");
  }
  
  const versionMadeBy = readUInt16LE(buf, offset + 4);
  const versionNeeded = readUInt16LE(buf, offset + 6);
  const bitFlags = readUInt16LE(buf, offset + 8);
  const compressionMethod = readUInt16LE(buf, offset + 10);
  const lastModTime = readUInt16LE(buf, offset + 12);
  const lastModDate = readUInt16LE(buf, offset + 14);
  const crc32 = readUInt32LE(buf, offset + 16);
  const compressedSize = readUInt32LE(buf, offset + 20);
  const uncompressedSize = readUInt32LE(buf, offset + 24);
  const fileNameLength = readUInt16LE(buf, offset + 28);
  const extraFieldLength = readUInt16LE(buf, offset + 30);
  const fileCommentLength = readUInt16LE(buf, offset + 32);
  const diskNumberStart = readUInt16LE(buf, offset + 34);
  const internalFileAttr = readUInt16LE(buf, offset + 36);
  const externalFileAttr = readUInt32LE(buf, offset + 38);
  const localHeaderOffset = readUInt32LE(buf, offset + 42);
  
  let pos = offset + 46;
  const fileName = buf.subarray(pos, pos + fileNameLength).toString("utf8");
  pos += fileNameLength;
  const extraField = buf.subarray(pos, pos + extraFieldLength);
  pos += extraFieldLength;
  const fileComment = fileCommentLength > 0 
    ? buf.subarray(pos, pos + fileCommentLength).toString("utf8") 
    : "";
  
  return {
    versionMadeBy,
    versionNeeded,
    bitFlags,
    compressionMethod,
    lastModTime,
    lastModDate,
    crc32,
    compressedSize,
    uncompressedSize,
    fileName,
    extraField,
    fileComment,
    diskNumberStart,
    internalFileAttr,
    externalFileAttr,
    localHeaderOffset,
    isDirectory: fileName.endsWith("/"),
  };
}

/**
 * Parse a Local File Header
 */
function parseLocalFileHeader(buf, offset) {
  if (buf.readUInt32LE(offset) !== ZIP_LOCAL_FILE_HEADER_SIGNATURE) {
    throw new Error("Invalid Local File Header signature");
  }
  
  const versionNeeded = readUInt16LE(buf, offset + 4);
  const bitFlags = readUInt16LE(buf, offset + 6);
  const compressionMethod = readUInt16LE(buf, offset + 8);
  const lastModTime = readUInt16LE(buf, offset + 10);
  const lastModDate = readUInt16LE(buf, offset + 12);
  const crc32 = readUInt32LE(buf, offset + 14);
  const compressedSize = readUInt32LE(buf, offset + 18);
  const uncompressedSize = readUInt32LE(buf, offset + 22);
  const fileNameLength = readUInt16LE(buf, offset + 26);
  const extraFieldLength = readUInt16LE(buf, offset + 28);
  
  let pos = offset + 30;
  const fileName = buf.subarray(pos, pos + fileNameLength).toString("utf8");
  pos += fileNameLength;
  const extraField = buf.subarray(pos, pos + extraFieldLength);
  
  return {
    versionNeeded,
    bitFlags,
    compressionMethod,
    lastModTime,
    lastModDate,
    crc32,
    compressedSize,
    uncompressedSize,
    fileName,
    extraField,
    headerSize: 30 + fileNameLength + extraFieldLength,
  };
}

/**
 * Extract a ZIP file to a target directory
 */
async function extractZip(zipBuf, targetDir) {
  // Ensure target directory exists
  await fs.mkdir(targetDir, { recursive: true });
  
  // Find and parse the End of Central Directory
  const eocdOffset = findEndOfCentralDirectory(zipBuf);
  const eocd = parseEndOfCentralDirectory(zipBuf, eocdOffset);
  
  // Read the Central Directory
  const cdStart = eocd.cdOffset;
  const cdEnd = cdStart + eocd.cdSize;
  const cdBuf = zipBuf.subarray(cdStart, cdEnd);
  
  let pos = 0;
  const entries = [];
  
  // Parse all Central Directory entries
  for (let i = 0; i < eocd.totalCdRecords; i++) {
    const entry = parseCentralDirectoryEntry(cdBuf, pos);
    entries.push(entry);
    pos += 46 + entry.fileNameLength + entry.extraFieldLength + entry.fileCommentLength;
  }
  
  // Extract each file
  const extractedFiles = [];
  
  for (const entry of entries) {
    // Skip directory entries (they're created automatically when files are written)
    if (entry.isDirectory) {
      continue;
    }
    
    // Read the Local File Header
    const lfhOffset = entry.localHeaderOffset;
    const lfh = parseLocalFileHeader(zipBuf, lfhOffset);
    
    // Data starts after the local file header
    const dataOffset = lfhOffset + lfh.headerSize;
    const compressedData = zipBuf.subarray(dataOffset, dataOffset + lfh.compressedSize);
    
    // Decompress the data
    let decompressedData;
    try {
      decompressedData = await decompressData(compressedData, lfh.compressionMethod);
    } catch (err) {
      // Failed to decompress - skip this file
      continue;
    }
    
    // Create the target file path
    // Use the central directory fileName as it's more reliable
    const filePath = path.join(targetDir, entry.fileName);
    
    // Create parent directories if needed
    const dir = path.dirname(filePath);
    if (dir !== targetDir) {
      await fs.mkdir(dir, { recursive: true });
    }
    
    // Write the file
    await fs.writeFile(filePath, decompressedData);
    extractedFiles.push(filePath);
  }
  
  return { entries, extractedFiles, count: extractedFiles.length };
}

// ---- tool definitions ---------------------------------------------------

const TOOLS = [
  {
    name: "list_files",
    description: "List files and directories inside the sandboxed temp directory.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Relative directory to list. Defaults to root." },
        recursive: { type: "boolean", description: "List recursively." },
      },
    },
  },
  {
    name: "read_file",
    description: "Read the contents of a file in the sandboxed temp directory.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Relative file path." },
      },
      required: ["path"],
    },
  },
  {
    name: "write_file",
    description:
      "Write (or append) text content to a file in the sandboxed temp directory. Creates parent directories as needed.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Relative file path." },
        content: { type: "string", description: "Text content to write." },
        append: { type: "boolean", description: "Append instead of overwrite." },
      },
      required: ["path", "content"],
    },
  },
  {
    name: "delete_file",
    description: "Delete a file in the sandboxed temp directory.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Relative file path." },
      },
      required: ["path"],
    },
  },
  {
    name: "unzip_file",
    description: "Extract a ZIP file to a directory in the sandboxed temp directory.",
    inputSchema: {
      type: "object",
      properties: {
        zipPath: { type: "string", description: "Relative path to the ZIP file." },
        extractTo: { 
          type: "string", 
          description: "Relative path to the directory to extract to. Defaults to current directory." 
        },
      },
      required: ["zipPath"],
    },
  },
];

async function callTool(name, args) {
  args = args || {};
  
  switch (name) {
    case "list_files": {
      const relPath = args.path ?? ".";
      const recursive = !!args.recursive;
      const target = await resolveSafe(relPath);
      const stat = await fs.stat(target).catch(() => null);
      if (!stat || !stat.isDirectory()) {
        throw new Error(`Not a directory: ${relPath}`);
      }
      const files = recursive
        ? await withTimeout(listFilesRecursive(target), OPERATION_TIMEOUT)
        : await withTimeout(
            Promise.all(
              (await fs.readdir(target, { withFileTypes: true })).map(async (entry) => {
                const full = path.join(target, entry.name);
                let realFull = full;
                
                // Only resolve symlinks if ALLOW_SYMLINKS is false
                if (!ALLOW_SYMLINKS) {
                  try {
                    realFull = await fs.realpath(full);
                  } catch (err) {
                    if (err.code === "ENOENT") {
                      // Entry was deleted during listing; skip it
                      return null;
                    }
                    throw err;
                  }
                }
                
                const rel = path.relative(target, realFull);
                if (entry.isDirectory()) return { path: rel, type: "directory" };
                let s;
                try {
                  s = await fs.stat(realFull);
                } catch (err) {
                  if (err.code === "ENOENT") {
                    return null;
                  }
                  throw err;
                }
                return { path: rel, type: "file", size: s.size };
              })
            ).then((results) => results.filter(Boolean)),
            OPERATION_TIMEOUT
          );
      // Return relative root to avoid path disclosure
      return { root: '.', files };
    }

    case "read_file": {
      if (typeof args.path !== "string") throw new Error("Missing required argument: path");
      const target = await resolveSafe(args.path);
      const stat = await fs.stat(target);
      if (stat.size > MAX_FILE_SIZE) {
        throw new Error(`File exceeds maximum size of ${MAX_FILE_SIZE} bytes`);
      }
      return await withTimeout(fs.readFile(target, "utf-8"), OPERATION_TIMEOUT);
    }

    case "write_file": {
      if (typeof args.path !== "string") throw new Error("Missing required argument: path");
      if (typeof args.content !== "string") throw new Error("Missing required argument: content");
      if (args.content.length > MAX_FILE_SIZE) {
        throw new Error(`Content exceeds maximum size of ${MAX_FILE_SIZE} bytes`);
      }
      const target = await resolveSafe(args.path);
      await withTimeout(
        (async () => {
          await fs.mkdir(path.dirname(target), { recursive: true });
          if (args.append) {
            await fs.appendFile(target, args.content, "utf-8");
          } else {
            await fs.writeFile(target, args.content, "utf-8");
          }
        })(),
        OPERATION_TIMEOUT
      );
      // Don't echo user input in response
      return `Wrote ${args.content.length} bytes`;
    }

    case "delete_file": {
      if (typeof args.path !== "string") throw new Error("Missing required argument: path");
      const target = await resolveSafe(args.path);
      await withTimeout(fs.unlink(target), OPERATION_TIMEOUT);
      // Don't echo user input in response
      return "Deleted file";
    }

    case "unzip_file": {
      if (typeof args.zipPath !== "string") {
        throw new Error("Missing required argument: zipPath");
      }
      
      const zipFilePath = await resolveSafe(args.zipPath);
      const extractToPath = args.extractTo 
        ? await resolveSafe(args.extractTo) 
        : await resolveSafe(".");
      
      // Check that the zip file exists
      const zipStat = await fs.stat(zipFilePath);
      if (!zipStat.isFile()) {
        throw new Error(`Not a file: ${args.zipPath}`);
      }
      
      // Check file size limit (use existing MAX_FILE_SIZE)
      if (zipStat.size > MAX_FILE_SIZE) {
        throw new Error(`ZIP file exceeds maximum size of ${MAX_FILE_SIZE} bytes`);
      }
      
      // Read the ZIP file
      const zipBuf = await withTimeout(fs.readFile(zipFilePath), OPERATION_TIMEOUT);
      
      // Extract the ZIP
      const result = await withTimeout(extractZip(zipBuf, extractToPath), OPERATION_TIMEOUT);
      
      return {
        extractedCount: result.count,
        files: result.extractedFiles.map(f => path.relative(ROOT_DIR, f)),
      };
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ---- minimal MCP-over-stdio JSON-RPC server -----------------------------

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function ok(id, result) {
  send({ jsonrpc: "2.0", id, result });
}

function err(id, code, message) {
  send({ jsonrpc: "2.0", id, error: { code, message } });
}

async function handleRequest(msg) {
  // Validate JSON-RPC version
  if (msg.jsonrpc !== "2.0") {
    // Non-compliant message; could be pre-2.0 or just malformed
    // For notifications (id === undefined), we don't send errors
    if (msg.id !== undefined) {
      err(msg.id, -32600, "Invalid JSON-RPC version");
    }
    return;
  }

  const { id, method, params } = msg;

  try {
    switch (method) {
      case "initialize": {
        ok(id, {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "mcp-tmpfs-server", version: "1.0.0" },
        });
        return;
      }

      case "notifications/initialized":
        // notification, no response expected
        return;

      case "tools/list": {
        ok(id, { tools: TOOLS });
        return;
      }

      case "tools/call": {
        const { name, arguments: callArgs } = params || {};
        try {
          const result = await withTimeout(callTool(name, callArgs), OPERATION_TIMEOUT);
          const text = typeof result === "string" ? result : JSON.stringify(result, null, 2);
          ok(id, { content: [{ type: "text", text }], isError: false });
        } catch (toolErr) {
          ok(id, { content: [{ type: "text", text: `Error: ${toolErr.message}` }], isError: true });
        }
        return;
      }

      case "ping": {
        ok(id, {});
        return;
      }

      default:
        if (id !== undefined) err(id, -32601, `Method not found: ${method}`);
        return;
    }
  } catch (e) {
    if (id !== undefined) err(id, -32603, e.message);
  }
}

async function main() {
  await fs.mkdir(ROOT_DIR, { recursive: true });

  // Process requests one at a time, in the order they arrive, so that
  // e.g. a write_file is fully done before the next request (like a
  // subsequent read_file) starts.
  let queue = Promise.resolve();

  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on("line", (line) => {
    line = line.trim();
    if (!line) return;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return; // ignore malformed lines
    }
    queue = queue.then(() => handleRequest(msg));
  });
}

main();
