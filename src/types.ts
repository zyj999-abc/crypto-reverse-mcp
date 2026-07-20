/**
 * Shared types for crypto-reverse-mcp tools
 * Matches the MCP SDK's expected ToolResult shape.
 */
export interface McpToolResult {
  [x: string]: unknown;
  content: Array<
    | { type: 'text'; text: string; [x: string]: unknown }
    | { type: 'image'; data: string; mimeType: string; [x: string]: unknown }
  >;
  isError?: boolean;
}
