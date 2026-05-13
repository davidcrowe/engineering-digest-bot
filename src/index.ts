/**
 * Governed agent — Anthropic SDK + ACP.
 *
 * Pre-tool: ACP evaluates policy (allow / deny / redact).
 * Post-tool: ACP audits the output and scans for PII.
 * Outbound vendor calls: route through acpFetch for credential brokering.
 *
 * You own the tools. ACP owns identity, policy, and audit.
 */
import Anthropic from "@anthropic-ai/sdk";
import express, { type Request, type Response } from "express";
import { governHandlers, withContext } from "@agenticcontrolplane/governance-anthropic";
import { acpCall } from "./acpClient.js";

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
if (!ANTHROPIC_API_KEY) throw new Error("Set ANTHROPIC_API_KEY in .env");

const MODEL = "gemini-2.5-pro";
const MAX_ROUNDS = 10;

const SYSTEM_PROMPT = 
  `You are an end-of-day Slack digest agent for the #engineering channel. Your job is to read the last 24 hours of messages, summarize them into four sections, and post the summary back to the channel.

## Your workflow every run:

1. **Recall prior coverage (START OF RUN)**
   - Call memory.search with query "last_processed_message_timestamp" to retrieve the timestamp of the last message you processed in the previous run.
   - If found, use that timestamp as your starting point. If not found (first run), fetch messages from the last 24 hours.

2. **Fetch new messages**
   - Call slack.getChannelHistory for #engineering, filtering messages newer than the last processed timestamp (or last 24 hours if first run).
   - If no new messages exist, post a brief note that there were no new messages today and exit.

3. **Analyze and summarize**
   - Read through all new messages and categorize them into:
     (1) **Decisions made**: Any conclusions, commitments, or finalized choices (e.g., "We'll use Postgres," "Shipping feature X on Friday").
     (2) **Open questions**: Unresolved asks, requests for input, or discussions without clear resolution.
     (3) **Blockers**: Explicit blockers, dependencies, or issues preventing progress.
     (4) **Most active people**: List the 3–5 people who posted the most messages or drove the most discussion.
   - If a section has no items, write "None today."
   - Use a clear, professional, and concise tone. Bullet points are preferred.

4. **Post the summary**
   - Search for an existing message in the channel with the text "End-of-day digest" posted today. If found, reply to it as a threaded message.
   - If no such message exists, create a new message with the subject line "End-of-day digest" and post your summary as a reply in the thread.
   - Format:
     \`\`\`
     **End-of-day summary for [date]**
     
     **1. Decisions made:**
     • [item]
     • [item]
     
     **2. Open questions:**
     • [item]
     
     **3. Blockers:**
     • [item]
     
     **4. Most active contributors:**
     • [name] ([X] messages)
     \`\`\`

5. **Save memory (END OF RUN)**
   - Call memory.save to record the timestamp of the latest message you processed this run (key: "last_processed_message_timestamp", value: the timestamp).
   - This ensures the next run starts where you left off and never duplicates summaries.

## Constraints:
- Only process messages from #engineering.
- Never summarize the same message twice across runs.
- If you encounter errors (e.g., Slack API failure), log the issue in memory and retry fetching messages once before exiting gracefully.
- Keep summaries concise: aim for 10–15 bullet points total across all four sections.`;

const anthropic = new Anthropic({ apiKey: ANTHROPIC_API_KEY });
const app = express();
app.use(express.json());

// ── Tool schemas (what Claude sees) ───────────────────────────────

const tools: Anthropic.Tool[] = [
  {
    name: "slack_getChannelHistory",
    description: "Get recent messages from a Slack channel.",
    input_schema: {
        "type": "object",
        "properties": {
            "channel": {
                "type": "string",
                "description": "Channel ID"
            },
            "limit": {
                "type": "number",
                "description": "Number of messages (default 25, max 100)",
                "default": 25
            }
        },
        "required": [
            "channel"
        ],
        "additionalProperties": false
    },
  },
  {
    name: "slack_searchMessages",
    description: "Search messages across the Slack workspace.",
    input_schema: {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search query"
            },
            "count": {
                "type": "number",
                "description": "Number of results (default 20, max 100)",
                "default": 20
            }
        },
        "required": [
            "query"
        ],
        "additionalProperties": false
    },
  },
  {
    name: "slack_sendMessage",
    description: "Post a message to a Slack channel or DM.",
    input_schema: {
        "type": "object",
        "properties": {
            "channel": {
                "type": "string",
                "description": "Channel ID (e.g. C01234567)"
            },
            "text": {
                "type": "string",
                "description": "Message text"
            },
            "thread_ts": {
                "type": "string",
                "description": "Thread timestamp to reply in (optional)"
            }
        },
        "required": [
            "channel",
            "text"
        ],
        "additionalProperties": false
    },
  },
  {
    name: "memory_save",
    description: "Save a fact, preference, or important context about the user for future conversations. Use this when the user says 'remember that...' or when you learn something important about them (e.g., preferred response style, project details, team members, processes).",
    input_schema: {
        "type": "object",
        "properties": {
            "content": {
                "type": "string",
                "description": "The fact or preference to remember (be specific and concise)"
            },
            "category": {
                "type": "string",
                "enum": [
                    "preference",
                    "fact",
                    "project",
                    "relationship",
                    "process"
                ],
                "description": "Category of the memory (default: fact)"
            },
            "tags": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Optional tags for easier retrieval"
            }
        },
        "required": [
            "content"
        ]
    },
  },
  {
    name: "memory_search",
    description: "Search the user's saved memories by keyword. Use this to recall previously saved context about the user's preferences, projects, team members, or processes.",
    input_schema: {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Keywords to search for in memories"
            },
            "category": {
                "type": "string",
                "enum": [
                    "preference",
                    "fact",
                    "project",
                    "relationship",
                    "process"
                ],
                "description": "Optional: filter by category"
            }
        },
        "required": [
            "query"
        ]
    },
  },
];

// ── Tool handlers (your implementations, wrapped in ACP policy) ───
// Stubs return a placeholder — replace each body with real logic.
// governHandlers wraps each one with pre-policy + post-audit calls.

const handlers = governHandlers({
  slack_getChannelHistory: async (input: Record<string, unknown>) => {
      // Tool: slack.getChannelHistory
      // Routes through the ACP gateway by default — real implementation runs
      // server-side with governance + audit. To self-host: replace this body
      // with your own code.
      return acpCall("slack.getChannelHistory", input);
  },
  slack_searchMessages: async (input: Record<string, unknown>) => {
      // Tool: slack.searchMessages
      // Routes through the ACP gateway by default — real implementation runs
      // server-side with governance + audit. To self-host: replace this body
      // with your own code.
      return acpCall("slack.searchMessages", input);
  },
  slack_sendMessage: async (input: Record<string, unknown>) => {
      // Tool: slack.sendMessage
      // Routes through the ACP gateway by default — real implementation runs
      // server-side with governance + audit. To self-host: replace this body
      // with your own code.
      return acpCall("slack.sendMessage", input);
  },
  memory_save: async (input: Record<string, unknown>) => {
      // Tool: memory.save
      // Routes through the ACP gateway by default — real implementation runs
      // server-side with governance + audit. To self-host: replace this body
      // with your own code.
      return acpCall("memory.save", input);
  },
  memory_search: async (input: Record<string, unknown>) => {
      // Tool: memory.search
      // Routes through the ACP gateway by default — real implementation runs
      // server-side with governance + audit. To self-host: replace this body
      // with your own code.
      return acpCall("memory.search", input);
  },
});

// ── Request handler ───────────────────────────────────────────────

app.post("/run", async (req: Request, res: Response) => {
  const auth = req.header("authorization") ?? "";
  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing Bearer token" });
  }
  const token = auth.slice("Bearer ".length).trim();
  const prompt: string = req.body?.prompt ?? "";
  if (!prompt) return res.status(400).json({ error: "prompt required" });

  await withContext({ userToken: token }, async () => {
    const messages: Anthropic.MessageParam[] = [{ role: "user", content: prompt }];
    for (let i = 0; i < MAX_ROUNDS; i++) {
      const msg = await anthropic.messages.create({
        model: MODEL,
        max_tokens: 4096,
        system: SYSTEM_PROMPT,
        tools,
        messages,
      });
      messages.push({ role: "assistant", content: msg.content });

      if (msg.stop_reason !== "tool_use") {
        const text = msg.content
          .filter((b): b is Anthropic.TextBlock => b.type === "text")
          .map((b) => b.text)
          .join("\n");
        return res.json({ result: text, rounds: i + 1 });
      }

      const toolResults: Anthropic.ToolResultBlockParam[] = [];
      for (const block of msg.content) {
        if (block.type !== "tool_use") continue;
        const handler = handlers[block.name];
        const output = handler
          ? await handler(block.input as Record<string, unknown>)
          : `tool_error: unknown tool "${block.name}"`;
        toolResults.push({
          type: "tool_result",
          tool_use_id: block.id,
          content: typeof output === "string" ? output : JSON.stringify(output),
        });
      }
      messages.push({ role: "user", content: toolResults });
    }
    res.status(500).json({ error: "max iterations reached" });
  });
});

const port = Number(process.env.PORT ?? 8000);
app.listen(port, () => console.log(`Listening on :${port}`));
