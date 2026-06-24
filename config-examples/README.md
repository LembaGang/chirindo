# Config examples

Drop-in templates for putting Chirindo in front of your real MCP server.
Both files have the same shape; pick the one for your client.

| File | Where it goes |
|---|---|
| `cursor-mcp.json` | `<your-project>/.cursor/mcp.json` (or `~/.cursor/mcp.json`) |
| `claude_desktop_config.json` | macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`  ·  Windows: `%APPDATA%\Claude\claude_desktop_config.json` |

## Two things to change

1. **`<ABSOLUTE-PATH-TO-CHIRINDO>`** — the directory where you installed
   Chirindo. Replace every occurrence with an absolute path (Cursor and
   Claude Desktop launch MCP servers from a process tree whose `PATH` is
   not always your shell's, so relative paths and bare binary names are
   unreliable). Example: `C:/Users/you/chirindo` on Windows,
   `/Users/you/chirindo` on macOS.

2. **The line after `"--"`** — the command for *your* real downstream MCP
   server. The template ships with `npx -y @your-org/your-mcp-server`
   as a deliberately-invalid placeholder, so a forgotten edit fails loudly
   instead of silently launching nothing. Examples:

   ```jsonc
   //  ▼  the documented default (npx-form, works on every platform)
   "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"

   //  ▼  fallback if `npx` is not on the client's PATH
   //     (Cursor on Windows in particular has been observed missing it)
   "--", "node", "/abs/path/to/your-server/dist/index.js"
   ```

After the swap, restart your client. You should see `my-server-gated` in
its MCP indicator. Receipts will appear in
`<ABSOLUTE-PATH-TO-CHIRINDO>/.gate/sessions/<session-id>.jsonl`.

## Why `node <chirindo>/dist/cli.js` and not the `chirindo` binary

Until the install mechanism is published, the launcher form above does
not assume `chirindo` is on `$PATH`. Once that lands, the templates
will collapse to a single `"command": "chirindo"` entry.
