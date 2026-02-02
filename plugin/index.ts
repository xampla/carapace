/**
 * 🦞 Carapace - OpenClaw Plugin
 *
 * The hard shell that protects your OpenClaw from prompt injection.
 * Uses Nova Framework + PromptIntel for detection.
 */

import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __filename = fileURLToPath(import.meta.url);
// Use realpathSync to resolve symlinks - ensures ../carapace.py finds the scanner
const __dirname = dirname(realpathSync(__filename));

// =============================================================================
// Types
// =============================================================================

interface PluginConfig {
  enabled?: boolean;
  scanToolOutputs?: boolean;
  blockDangerousCommands?: boolean;
  promptIntelApiKey?: string;
  enableSemantics?: boolean;
  enableLlm?: boolean;
  llmProvider?: string;
  llmApiKey?: string;
}

interface PluginApi {
  id: string;
  pluginConfig: PluginConfig;
  logger: {
    info: (msg: string) => void;
    warn: (msg: string) => void;
    error: (msg: string) => void;
  };
  on: (
    hookName: string,
    handler: (event: unknown, context?: unknown) => unknown,
    opts?: { priority?: number }
  ) => void;
  registerGatewayMethod: (
    method: string,
    handler: (params: unknown) => void
  ) => void;
}

interface ScanResult {
  safe: boolean;
  threats: Array<{
    rule: string;
    category: string;
    severity: string;
    matched: string;
  }>;
  count: number;
  highest_severity: string | null;
}

interface ToolResultPersistEvent {
  toolName?: string;
  message?: string | object;
}

interface BeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
}

interface BeforeToolCallResult {
  block?: boolean;
  blockReason?: string;
  params?: Record<string, unknown>;
}


// =============================================================================
// Configuration
// =============================================================================

const SCANNER_PATH = join(__dirname, "..", "carapace.py");
const PYTHON_PATH = process.env.PYTHON_PATH || "python3";

// High severity levels that trigger warnings
const HIGH_SEVERITY = new Set(["high", "critical"]);

// Tools whose output should be scanned for injection
const RISKY_OUTPUT_TOOLS = new Set(["exec", "shell", "bash", "read", "web_fetch"]);

// Tools that execute commands (scan with command scanner)
const COMMAND_EXEC_TOOLS = new Set(["exec", "shell", "bash"]);

// Tools that read files (scan path for suspicious patterns)
const FILE_READ_TOOLS = new Set(["read"]);

// Tools that fetch URLs (scan URL for suspicious patterns)
const WEB_FETCH_TOOLS = new Set(["web_fetch", "webfetch"]);

// Module-level config
let config: PluginConfig = {};
let apiKey: string | undefined;
let enableSemantics: boolean = false;
let enableLlm: boolean = false;
let llmProvider: string = "openai";
let llmApiKey: string | undefined;


// =============================================================================
// Scanner Interface
// =============================================================================

/**
 * Synchronous scan - required because tool_result_persist hook is synchronous.
 */
function scanSync(text: string, logger?: PluginApi["logger"]): ScanResult {
  const args = [SCANNER_PATH, "scan", text];

  if (enableSemantics) {
    args.push("--enable-semantics");
  }
  if (enableLlm) {
    args.push("--enable-llm");
  }
  if (!apiKey) {
    args.push("--offline");
  }

  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    PYTHONWARNINGS: "ignore",
  };
  if (apiKey) {
    env.PROMPTINTEL_API_KEY = apiKey;
  }
  if (llmApiKey) {
    if (llmProvider === "anthropic") {
      env.ANTHROPIC_API_KEY = llmApiKey;
    } else {
      env.OPENAI_API_KEY = llmApiKey;
    }
  }

  try {
    const result = spawnSync(PYTHON_PATH, args, { timeout: 30000, env, encoding: "utf-8" });

    // Exit codes: 0 = safe, 1 = threats found, other = error
    if (result.status !== 0 && result.status !== 1) {
      logger?.warn(`[carapace] Scanner exited with code ${result.status}`);
      return { safe: true, threats: [], count: 0, highest_severity: null };
    }

    const stdout = (result.stdout || "").trim();
    if (stdout.startsWith("{")) {
      return JSON.parse(stdout) as ScanResult;
    }
    logger?.warn(`[carapace] No JSON in scanner output`);
  } catch (err) {
    logger?.error(`[carapace] Scan error: ${err}`);
  }

  return { safe: true, threats: [], count: 0, highest_severity: null };
}

/**
 * Synchronous command scan - for before_tool_call hook.
 */
function scanCommandSync(command: string, logger?: PluginApi["logger"]): ScanResult {
  const args = [SCANNER_PATH, "command", command];

  if (enableSemantics) {
    args.push("--enable-semantics");
  }
  if (enableLlm) {
    args.push("--enable-llm");
  }

  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    PYTHONWARNINGS: "ignore",
  };
  if (llmApiKey) {
    if (llmProvider === "anthropic") {
      env.ANTHROPIC_API_KEY = llmApiKey;
    } else {
      env.OPENAI_API_KEY = llmApiKey;
    }
  }

  try {
    const result = spawnSync(PYTHON_PATH, args, { timeout: 30000, env, encoding: "utf-8" });

    if (result.status !== 0 && result.status !== 1) {
      logger?.warn(`[carapace] Command scanner exited with code ${result.status}`);
      return { safe: true, threats: [], count: 0, highest_severity: null };
    }

    const stdout = (result.stdout || "").trim();
    if (stdout.startsWith("{")) {
      return JSON.parse(stdout) as ScanResult;
    }
    logger?.warn(`[carapace] No JSON in command scanner output`);
  } catch (err) {
    logger?.error(`[carapace] Command scan error: ${err}`);
  }

  return { safe: true, threats: [], count: 0, highest_severity: null };
}

/**
 * Extract command string from tool params.
 */
function extractCommand(params: Record<string, unknown>): string | null {
  const commandKeys = ["command", "cmd", "script", "code", "input"];
  for (const key of commandKeys) {
    const val = params[key];
    if (typeof val === "string" && val.trim()) {
      return val;
    }
  }
  return null;
}

/**
 * Extract file path from tool params.
 */
function extractPath(params: Record<string, unknown>): string | null {
  const pathKeys = ["path", "file_path", "filepath", "file", "filename"];
  for (const key of pathKeys) {
    const val = params[key];
    if (typeof val === "string" && val.trim()) {
      return val;
    }
  }
  return null;
}

/**
 * Extract URL from tool params.
 */
function extractUrl(params: Record<string, unknown>): string | null {
  const urlKeys = ["url", "uri", "href", "link", "endpoint"];
  for (const key of urlKeys) {
    const val = params[key];
    if (typeof val === "string" && val.trim()) {
      return val;
    }
  }
  return null;
}

/**
 * Check if any threat is high severity.
 */
function hasHighSeverity(result: ScanResult): boolean {
  return result.threats.some((t) => HIGH_SEVERITY.has(t.severity));
}

// =============================================================================
// Plugin Registration
// =============================================================================

export default function register(api: PluginApi): void {
  config = api.pluginConfig ?? {};

  if (config.enabled === false) {
    api.logger.info("[carapace] Plugin disabled");
    return;
  }

  apiKey = config.promptIntelApiKey || process.env.PROMPTINTEL_API_KEY;
  enableSemantics = config.enableSemantics ?? false;
  enableLlm = config.enableLlm ?? false;
  llmProvider = config.llmProvider ?? "openai";
  llmApiKey = config.llmApiKey || process.env.OPENAI_API_KEY || process.env.ANTHROPIC_API_KEY;

  const features: string[] = [];
  if (apiKey) features.push("PromptIntel");
  if (enableSemantics) features.push("semantics");
  if (enableLlm) features.push(`LLM(${llmProvider})`);
  const status = features.length > 0 ? features.join(", ") : "local rules only";
  api.logger.info(`[carapace] 🦞 Protection active (${status})`);

  // =========================================================================
  // Hook: tool_result_persist - Scan tool outputs and prepend warnings
  // NOTE: This hook is SYNCHRONOUS - cannot use async/await
  // =========================================================================
  if (config.scanToolOutputs !== false) {
    api.on(
      "tool_result_persist",
      (event: ToolResultPersistEvent) => {
        if (!event.message) return undefined;

        // Only scan risky tools (normalize to lowercase for comparison)
        const toolNameLower = (event.toolName ?? "").toLowerCase();
        if (!RISKY_OUTPUT_TOOLS.has(toolNameLower)) {
          return undefined;
        }

        try {
          // Convert message to string if needed
          const messageStr = typeof event.message === "string"
            ? event.message
            : JSON.stringify(event.message);

          // Only scan first 2KB of output
          const outputToScan = messageStr.slice(0, 2048);
          const result = scanSync(outputToScan, api.logger);

          if (!result.safe) {
            const isHigh = hasHighSeverity(result);
            const severity = isHigh ? "high" : "low/med";
            const emoji = isHigh ? "🚨" : "⚠️";
            const category = result.threats[0]?.category?.split("/")[0] ?? "unknown";

            api.logger.warn(
              `[carapace] ${emoji} Detected ${result.count} threat(s) in ${event.toolName} output (${category}, ${severity})`
            );

            const warning = `${emoji} Carapace: Tool output may contain prompt injection (${category}, severity: ${severity})\n\n`;

            // Prepend warning to message content
            if (typeof event.message === "object" && event.message !== null) {
              const msg = event.message as Record<string, unknown>;
              if (Array.isArray(msg.content)) {
                return {
                  message: {
                    ...msg,
                    content: [{ type: "text", text: warning }, ...msg.content],
                  },
                };
              }
            }
          }
        } catch (err) {
          api.logger.error(`[carapace] Error scanning tool output: ${err}`);
        }

        return undefined;
      },
      { priority: 50 }
    );
  }

  // =========================================================================
  // Hook: before_tool_call - Block dangerous tool calls
  // =========================================================================
  if (config.blockDangerousCommands !== false) {
    api.on(
      "before_tool_call",
      (event: BeforeToolCallEvent): BeforeToolCallResult | undefined => {
        const toolNameLower = (event.toolName || "").toLowerCase();
        const params = event.params || {};

        let textToScan: string | null = null;
        let scanType: "command" | "text" = "text";
        let inputType = "input";

        // Determine what to scan based on tool type
        if (COMMAND_EXEC_TOOLS.has(toolNameLower)) {
          textToScan = extractCommand(params);
          scanType = "command";
          inputType = "command";
        } else if (FILE_READ_TOOLS.has(toolNameLower)) {
          textToScan = extractPath(params);
          inputType = "path";
        } else if (WEB_FETCH_TOOLS.has(toolNameLower)) {
          textToScan = extractUrl(params);
          inputType = "URL";
        } else {
          return undefined;
        }

        if (!textToScan) {
          return undefined;
        }

        try {
          // Use command scanner for exec tools, text scanner for others
          const result = scanType === "command"
            ? scanCommandSync(textToScan, api.logger)
            : scanSync(textToScan, api.logger);

          if (!result.safe) {
            const isHigh = hasHighSeverity(result);
            const category = result.threats[0]?.category?.split("/")[0] ?? "unknown";

            if (isHigh) {
              // Block high/critical severity threats
              const blockReason = `Blocked by Carapace: ${inputType} contains ${result.count} threat(s) (${category}, severity: ${result.highest_severity})`;
              api.logger.warn(`[carapace] BLOCKED ${toolNameLower}: ${blockReason}`);
              return {
                block: true,
                blockReason,
              };
            } else {
              // Log warning for low/medium severity but allow
              api.logger.warn(
                `[carapace] WARNING: ${toolNameLower} ${inputType} has ${result.count} threat(s) (${category}, severity: ${result.highest_severity}) - allowing`
              );
            }
          }
        } catch (err) {
          api.logger.error(`[carapace] Error scanning ${inputType}: ${err}`);
        }

        return undefined;
      },
      { priority: 100 } // High priority to run early
    );
  }

  // =========================================================================
  // RPC: carapace.scan - Manual scan endpoint
  // =========================================================================
  api.registerGatewayMethod(
    "carapace.scan",
    async ({
      respond,
      text,
    }: {
      respond: (ok: boolean, data: unknown) => void;
      text?: string;
    }) => {
      if (!text) {
        respond(false, { error: "Missing 'text' parameter" });
        return;
      }

      try {
        const result = scanSync(text, api.logger);
        respond(true, result);
      } catch {
        respond(false, { error: "Scan failed" });
      }
    }
  );

  // =========================================================================
  // RPC: carapace.scanCommand - Manual command scan endpoint
  // =========================================================================
  api.registerGatewayMethod(
    "carapace.scanCommand",
    async ({
      respond,
      command,
    }: {
      respond: (ok: boolean, data: unknown) => void;
      command?: string;
    }) => {
      if (!command) {
        respond(false, { error: "Missing 'command' parameter" });
        return;
      }

      try {
        const result = scanCommandSync(command, api.logger);
        respond(true, result);
      } catch {
        respond(false, { error: "Command scan failed" });
      }
    }
  );

  // =========================================================================
  // RPC: carapace.status - Plugin status endpoint
  // =========================================================================
  api.registerGatewayMethod(
    "carapace.status",
    ({ respond }: { respond: (ok: boolean, data: unknown) => void }) => {
      respond(true, {
        enabled: config.enabled !== false,
        promptIntelConfigured: !!apiKey,
        semanticsEnabled: enableSemantics,
        llmEnabled: enableLlm,
        config: {
          scanToolOutputs: config.scanToolOutputs !== false,
          blockDangerousCommands: config.blockDangerousCommands !== false,
        },
      });
    }
  );
}
