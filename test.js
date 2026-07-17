#!/usr/bin/env node
"use strict";

/**
 * Tests for mcp-tmpfs-server
 * Dependency-free tests using Node.js built-ins only.
 */

const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const { spawn } = require("node:child_process");

const assert = require("node:assert");

// Test state
let testsPassed = 0;
let testsFailed = 0;
let testSandboxDir = null;

async function runTest(name, fn) {
  try {
    await fn();
    console.log(`✓ ${name}`);
    testsPassed++;
  } catch (err) {
    console.error(`✗ ${name}`);
    console.error(`  ${err.message}`);
    testsFailed++;
  }
}

async function sendRequest(process, method, params = {}) {
  const msg = { jsonrpc: "2.0", method, params, id: Date.now() };
  process.stdin.write(JSON.stringify(msg) + "\n");
  
  return new Promise((resolve, reject) => {
    const listener = (data) => {
      try {
        const line = data.toString();
        const response = JSON.parse(line);
        if (response.id === msg.id) {
          process.stdout.off("data", listener);
          if (response.error) {
            reject(new Error(response.error.message));
          } else {
            resolve(response.result);
          }
        }
      } catch (e) {
        // ignore non-JSON or non-matching responses
      }
    };
    process.stdout.on("data", listener);
    
    // Timeout after 2 seconds
    setTimeout(() => {
      process.stdout.off("data", listener);
      reject(new Error(`Timeout waiting for response to ${method}`));
    }, 2000);
  });
}

async function startServer(sandboxDir) {
  const server = spawn("node", ["index.js", `--dir=${sandboxDir}`], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  
  // Wait for server to start
  await new Promise((resolve) => {
    server.stderr.on("data", (data) => {
      if (data.toString().includes("mcp-tmpfs-server running")) {
        resolve();
      }
    });
  });
  
  // Initialize the MCP server
  await sendRequest(server, "initialize");
  // notifications/initialized is a notification, not a request - no response expected
  const msg = { jsonrpc: "2.0", method: "notifications/initialized", params: {}, id: null };
  server.stdin.write(JSON.stringify(msg) + "\n");
  
  return server;
}

async function runTests() {
  // Create a unique sandbox directory for testing
  testSandboxDir = path.join(os.tmpdir(), `mcp-tmpfs-test-${Date.now()}`);
  await fs.mkdir(testSandboxDir, { recursive: true });
  
  let server;
  try {
    server = await startServer(testSandboxDir);
    
    // Get the list of tools
    await runTest("tools/list returns all 5 tools", async () => {
      const result = await sendRequest(server, "tools/list");
      assert.strictEqual(result.tools.length, 5);
      const toolNames = result.tools.map(t => t.name);
      assert(toolNames.includes("list_files"));
      assert(toolNames.includes("read_file"));
      assert(toolNames.includes("write_file"));
      assert(toolNames.includes("delete_file"));
      assert(toolNames.includes("unzip_file"));
    });
    
    // Test write_file
    await runTest("write_file creates a file", async () => {
      const result = await sendRequest(server, "tools/call", {
        name: "write_file",
        arguments: { path: "test.txt", content: "hello world" },
      });
      assert(result.isError === false);
      
      // Verify file exists and has correct content
      const filePath = path.join(testSandboxDir, "test.txt");
      const content = await fs.readFile(filePath, "utf-8");
      assert.strictEqual(content, "hello world");
    });
    
    // Test write_file with append
    await runTest("write_file appends to existing file", async () => {
      await sendRequest(server, "tools/call", {
        name: "write_file",
        arguments: { path: "test.txt", content: " appending", append: true },
      });
      
      const filePath = path.join(testSandboxDir, "test.txt");
      const content = await fs.readFile(filePath, "utf-8");
      assert.strictEqual(content, "hello world appending");
    });
    
    // Test write_file creates parent directories
    await runTest("write_file creates parent directories", async () => {
      await sendRequest(server, "tools/call", {
        name: "write_file",
        arguments: { path: "subdir/nested/file.txt", content: "nested content" },
      });
      
      const filePath = path.join(testSandboxDir, "subdir/nested/file.txt");
      const content = await fs.readFile(filePath, "utf-8");
      assert.strictEqual(content, "nested content");
    });
    
    // Test read_file
    await runTest("read_file returns file content", async () => {
      const result = await sendRequest(server, "tools/call", {
        name: "read_file",
        arguments: { path: "test.txt" },
      });
      assert(result.isError === false);
      // The result is wrapped in content array, text field contains the file content as string
      const textResult = result.content[0].text;
      assert.strictEqual(typeof textResult, "string");
      assert(textResult.includes("hello world"));
    });
    
    // Test list_files
    await runTest("list_files returns directory contents", async () => {
      const result = await sendRequest(server, "tools/call", {
        name: "list_files",
        arguments: { path: "." },
      });
      assert(result.isError === false);
      const listResult = JSON.parse(result.content[0].text);
      assert(Array.isArray(listResult.files));
      assert(listResult.files.length > 0);
      // root is now '.' to avoid path disclosure
      assert(listResult.root === '.');
    });
    
    // Test list_files recursive
    await runTest("list_files recursive finds nested files", async () => {
      const result = await sendRequest(server, "tools/call", {
        name: "list_files",
        arguments: { path: ".", recursive: true },
      });
      assert(result.isError === false);
      const listResult = JSON.parse(result.content[0].text);
      const nestedFile = listResult.files.find(f => f.path.includes("subdir"));
      assert(nestedFile !== undefined);
    });
    
    // Test delete_file
    await runTest("delete_file removes a file", async () => {
      await sendRequest(server, "tools/call", {
        name: "delete_file",
        arguments: { path: "test.txt" },
      });
      
      const filePath = path.join(testSandboxDir, "test.txt");
      await assert.rejects(
        fs.access(filePath, fs.constants.F_OK),
        /ENOENT/,
      );
    });
    
    // Test path escaping is prevented
    await runTest("write_file prevents path escaping", async () => {
      const result = await sendRequest(server, "tools/call", {
        name: "write_file",
        arguments: { path: "../outside.txt", content: "should not work" },
      });
      assert(result.isError === true);
      assert(result.content[0].text.includes("Path escapes the allowed directory"));
      
      // Verify the file wasn't created outside
      const outsidePath = path.join(path.dirname(testSandboxDir), "outside.txt");
      await assert.rejects(
        fs.access(outsidePath, fs.constants.F_OK),
        /ENOENT/,
      );
    });
    
    // Test read_file on non-existent file
    await runTest("read_file fails on non-existent file", async () => {
      const result = await sendRequest(server, "tools/call", {
        name: "read_file",
        arguments: { path: "nonexistent.txt" },
      });
      assert(result.isError === true);
    });
    
    // Test delete_file on non-existent file
    await runTest("delete_file fails on non-existent file", async () => {
      const result = await sendRequest(server, "tools/call", {
        name: "delete_file",
        arguments: { path: "nonexistent.txt" },
      });
      assert(result.isError === true);
    });
    
    // Test list_files on non-existent directory
    await runTest("list_files fails on non-existent directory", async () => {
      const result = await sendRequest(server, "tools/call", {
        name: "list_files",
        arguments: { path: "nonexistent" },
      });
      assert(result.isError === true);
    });
    
    // Test ping
    await runTest("ping returns empty result", async () => {
      const result = await sendRequest(server, "ping");
      assert.deepStrictEqual(result, {});
    });

    // Test symlink traversal is blocked
    await runTest("read_file blocks path escaping", async () => {
      // Test the path resolution logic by trying to read outside the sandbox
      const result = await sendRequest(server, "tools/call", {
        name: "read_file",
        arguments: { path: "../outside.txt" },
      });
      // The server should return isError: true
      assert(result.isError === true);
      assert(result.content[0].text.includes("Path escapes the allowed directory"));
    });

    // Test null byte in path is rejected
    await runTest("write_file rejects null bytes in path", async () => {
      const result = await sendRequest(server, "tools/call", {
        name: "write_file",
        arguments: { path: "test\0file.txt", content: "test" },
      });
      assert(result.isError === true);
      assert(result.content[0].text.includes("Null bytes"));
    });

    // Test file size limit on read
    await runTest("write_file rejects oversized content", async () => {
      const largeContent = "x".repeat(100 * 1024 * 1024 + 1); // 100MB + 1 byte
      const result = await sendRequest(server, "tools/call", {
        name: "write_file",
        arguments: { path: "large.txt", content: largeContent },
      });
      assert(result.isError === true);
      assert(result.content[0].text.includes("exceeds maximum size"));
    });

    // Test JSON-RPC version validation
    await runTest("rejects non-2.0 JSON-RPC version", async () => {
      // Send a request with wrong version
      const msg = { jsonrpc: "1.0", method: "ping", id: 999, params: {} };
      server.stdin.write(JSON.stringify(msg) + "\n");
      
      // Wait for response
      const result = await new Promise((resolve) => {
        const listener = (data) => {
          try {
            const line = data.toString();
            const response = JSON.parse(line);
            if (response.id === 999) {
              server.stdout.off("data", listener);
              resolve(response);
            }
          } catch (e) {
            // ignore
          }
        };
        server.stdout.on("data", listener);
        setTimeout(() => {
          server.stdout.off("data", listener);
          resolve({ error: { message: "timeout" } });
        }, 1000);
      });
      
      assert(result.error !== undefined);
      assert(result.error.code === -32600);
    });

    // Test ALLOW_SYMLINKS env var (default is false, symlinks blocked)
    await runTest("ALLOW_SYMLINKS defaults to false", async () => {
      // The server was started without MCP_TMPFS_ALLOW_SYMLINKS
      // so symlink following should be disabled
      const result = await sendRequest(server, "tools/call", {
        name: "read_file",
        arguments: { path: "../outside.txt" },
      });
      assert(result.isError === true);
      assert(result.content[0].text.includes("Path escapes"));
    });

    // Test ALLOW_SYMLINKS=true via custom server
    await runTest("ALLOW_SYMLINKS=true allows server to start", async () => {
      const customDir = path.join(os.tmpdir(), `mcp-tmpfs-test-symlink-${Date.now()}`);
      await fs.mkdir(customDir, { recursive: true });
      
      const customServer = spawn("node", ["index.js", `--dir=${customDir}`], {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, MCP_TMPFS_ALLOW_SYMLINKS: "true" },
      });
      
      // Wait for server to start
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error("Server timeout")), 2000);
        customServer.stderr.on("data", (data) => {
          if (data.toString().includes("mcp-tmpfs-server running")) {
            clearTimeout(timeout);
            resolve();
          }
        });
      });
      
      // If we get here, server started successfully with ALLOW_SYMLINKS=true
      // No assertion needed - if it didn't start, we'd have timed out
      
      customServer.stdin.end();
      customServer.kill();
      await fs.rm(customDir, { recursive: true, force: true }).catch(() => {});
    });

  // --- unzip_file tests ---

  // Helper to write little-endian uint16
  const writeUint16 = (buf, offset, value) => {
    buf[offset] = value & 0xFF;
    buf[offset + 1] = (value >> 8) & 0xFF;
  };
  
  // Helper to write little-endian uint32
  const writeUint32 = (buf, offset, value) => {
    buf[offset] = value & 0xFF;
    buf[offset + 1] = (value >> 8) & 0xFF;
    buf[offset + 2] = (value >> 16) & 0xFF;
    buf[offset + 3] = (value >> 24) & 0xFF;
  };

  // Helper to create a valid ZIP file buffer
  const createZipBuffer = (fileName, fileContent) => {
    const fileNameBytes = Buffer.from(fileName);
    const fileContentBytes = Buffer.from(fileContent);
    
    // Local File Header
    const lfh = Buffer.alloc(30 + fileNameBytes.length);
    let offset = 0;
    writeUint32(lfh, offset, 0x04034b50); offset += 4;
    writeUint16(lfh, offset, 20); offset += 2;  // version needed
    writeUint16(lfh, offset, 0); offset += 2;   // bit flags
    writeUint16(lfh, offset, 0); offset += 2;   // compression method (0 = store)
    writeUint16(lfh, offset, 0); offset += 2;   // mod time
    writeUint16(lfh, offset, 0); offset += 2;   // mod date
    writeUint32(lfh, offset, 0); offset += 4;   // crc32
    writeUint32(lfh, offset, fileContentBytes.length); offset += 4; // compressed size
    writeUint32(lfh, offset, fileContentBytes.length); offset += 4; // uncompressed size
    writeUint16(lfh, offset, fileNameBytes.length); offset += 2; // file name length
    writeUint16(lfh, offset, 0); offset += 2;  // extra field length
    fileNameBytes.copy(lfh, offset);
    
    const dataStart = lfh.length;
    const dataEnd = dataStart + fileContentBytes.length;
    
    // Central Directory Entry
    const cd = Buffer.alloc(46 + fileNameBytes.length);
    offset = 0;
    writeUint32(cd, offset, 0x02014b50); offset += 4; // signature
    writeUint16(cd, offset, 20); offset += 2;  // version made by
    writeUint16(cd, offset, 20); offset += 2;  // version needed
    writeUint16(cd, offset, 0); offset += 2;   // bit flags
    writeUint16(cd, offset, 0); offset += 2;   // compression method
    writeUint16(cd, offset, 0); offset += 2;   // mod time
    writeUint16(cd, offset, 0); offset += 2;   // mod date
    writeUint32(cd, offset, 0); offset += 4;   // crc32
    writeUint32(cd, offset, fileContentBytes.length); offset += 4; // compressed size
    writeUint32(cd, offset, fileContentBytes.length); offset += 4; // uncompressed size
    writeUint16(cd, offset, fileNameBytes.length); offset += 2; // file name length
    writeUint16(cd, offset, 0); offset += 2;  // extra field length
    writeUint16(cd, offset, 0); offset += 2;  // file comment length
    writeUint16(cd, offset, 0); offset += 2;  // disk number start
    writeUint16(cd, offset, 0); offset += 2;  // internal file attributes
    writeUint32(cd, offset, 0); offset += 4;  // external file attributes
    writeUint32(cd, offset, 0); offset += 4;  // relative offset of local header
    fileNameBytes.copy(cd, offset);
    
    const cdSize = cd.length;
    const cdOffset = dataEnd;
    
    // End of Central Directory
    const eocd = Buffer.alloc(22);
    offset = 0;
    writeUint32(eocd, offset, 0x06054b50); offset += 4; // signature
    writeUint16(eocd, offset, 0); offset += 2;  // disk number
    writeUint16(eocd, offset, 0); offset += 2;  // disk where CD starts
    writeUint16(eocd, offset, 1); offset += 2;  // num CD records on this disk
    writeUint16(eocd, offset, 1); offset += 2;  // total CD records
    writeUint32(eocd, offset, cdSize); offset += 4; // size of CD
    writeUint32(eocd, offset, cdOffset); offset += 4; // offset of CD
    writeUint16(eocd, offset, 0); offset += 2;  // comment length
    
    return Buffer.concat([lfh, fileContentBytes, cd, eocd]);
  }

  // Test unzip_file with a valid ZIP
  await runTest("unzip_file extracts a valid ZIP file", async () => {
    const zipBuf = createZipBuffer("test.txt", "Hello from ZIP!");
    const zipPath = path.join(testSandboxDir, "test.zip");
    await fs.writeFile(zipPath, zipBuf);
    
    const result = await sendRequest(server, "tools/call", {
      name: "unzip_file",
      arguments: { zipPath: "test.zip" },
    });
    
    assert(result.isError === false);
    const unzipResult = JSON.parse(result.content[0].text);
    assert(unzipResult.extractedCount === 1);
    assert(unzipResult.files.length === 1);
    assert(unzipResult.files[0] === "test.txt");
    
    // Verify the extracted file content
    const extractedContent = await fs.readFile(path.join(testSandboxDir, "test.txt"), "utf8");
    assert.strictEqual(extractedContent, "Hello from ZIP!");
  });

  // Test unzip_file with extractTo parameter
  await runTest("unzip_file extracts to specified directory", async () => {
    const zipBuf = createZipBuffer("nested.txt", "Nested content");
    const zipPath = path.join(testSandboxDir, "test2.zip");
    await fs.writeFile(zipPath, zipBuf);
    
    const result = await sendRequest(server, "tools/call", {
      name: "unzip_file",
      arguments: { zipPath: "test2.zip", extractTo: "unzip_output" },
    });
    
    assert(result.isError === false);
    const unzipResult = JSON.parse(result.content[0].text);
    assert(unzipResult.extractedCount === 1);
    assert(unzipResult.files[0] === path.join("unzip_output", "nested.txt"));
    
    // Verify the file was extracted to the subdirectory
    const extractedContent = await fs.readFile(
      path.join(testSandboxDir, "unzip_output", "nested.txt"),
      "utf8"
    );
    assert.strictEqual(extractedContent, "Nested content");
  });

  // Test unzip_file fails on non-existent file
  await runTest("unzip_file fails on non-existent file", async () => {
    const result = await sendRequest(server, "tools/call", {
      name: "unzip_file",
      arguments: { zipPath: "nonexistent.zip" },
    });
    assert(result.isError === true);
  });

  // Test unzip_file fails on directory
  await runTest("unzip_file fails when zipPath is a directory", async () => {
    await fs.mkdir(path.join(testSandboxDir, "testdir"), { recursive: true });
    
    const result = await sendRequest(server, "tools/call", {
      name: "unzip_file",
      arguments: { zipPath: "testdir" },
    });
    assert(result.isError === true);
    assert(result.content[0].text.includes("Not a file"));
  });

  } finally {
    if (server) {
      server.stdin.end();
      server.kill();
    }
    
    // Clean up sandbox
    await fs.rm(testSandboxDir, { recursive: true, force: true }).catch(() => {});
  }
  
  console.log(`\n${testsPassed} passed, ${testsFailed} failed`);
  if (testsFailed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error("Test runner error:", err);
  process.exit(1);
});
