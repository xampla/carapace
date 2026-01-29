/**
 * 🦞 Carapace - Moltbot Plugin
 *
 * The hard shell that protects your Moltbot from prompt injection.
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


// =============================================================================
// Configuration
// =============================================================================

const SCANNER_PATH = join(__dirname, "..", "carapace.py");
const PYTHON_PATH = process.env.PYTHON_PATH || "python3";

// High severity levels that trigger warnings
const HIGH_SEVERITY = new Set(["high", "critical"]);

// Tools whose output should be scanned for injection
const RISKY_TOOLS = ["exec", "shell", "bash", "Bash", "read", "Read", "web_fetch", "WebFetch"];

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

        // Only scan risky tools
        if (!RISKY_TOOLS.includes(event.toolName ?? "")) {
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
        },
      });
    }
  );
}
