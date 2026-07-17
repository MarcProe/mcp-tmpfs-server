# mcp-tmpfs-server

MCP server (stdio, JSON-RPC 2.0) with no dependencies. Exposes 5 tools scoped
to one sandbox directory:

- `list_files` — list files/dirs (`path`, `recursive`)
- `read_file` — read a text file (`path`)
- `write_file` — write or append a text file (`path`, `content`, `append`)
- `delete_file` — delete a file (`path`)
- `unzip_file` — extract a ZIP file (`zipPath`, `extractTo`)

All paths are relative to the sandbox root and are checked to prevent
`../` traversal outside it.

## Run

```
npx mcp-tmpfs-server
```

The package is published on npm, so you can run it from anywhere using the command above.

To run locally without npm: `node index.js`, or `npx .` from this folder.

## Sandbox directory

Defaults to `<os tmpdir>/mcp-tmpfs-server`. Override with:

```
npx mcp-tmpfs-server --dir=/path/to/dir
# or
MCP_TMPFS_DIR=/path/to/dir npx mcp-tmpfs-server
```

## Security options

By default, the server blocks symlink-based directory traversal for security.
To allow following symlinks (use with caution):

```
MCP_TMPFS_ALLOW_SYMLINKS=true npx mcp-tmpfs-server
# or
MCP_TMPFS_ALLOW_SYMLINKS=1 npx mcp-tmpfs-server
```

## Add to an MCP client (e.g. Claude Desktop config)

```json
{
  "mcpServers": {
    "tmpfs": {
      "command": "npx",
      "args": ["mcp-tmpfs-server"]
    }
  }
}
```

