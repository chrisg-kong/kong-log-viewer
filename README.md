# Kong HTTP Log Viewer

A self-contained viewer for Kong Gateway and AI Gateway traffic. Point the
`http-log` plugin at it and every request becomes readable — prompts as chat
transcripts, plugin behaviour laid out per request, MCP tool calls and A2A tasks
rendered properly, with token usage and cost alongside.

One container, one volume, no external dependencies.

## What it shows

**Traffic**
- Every request in a filterable table: timestamp, status, URI, latency,
  consumer, and the client app that made the call
- Filter by time range, type, status, provider, model, MCP method or tool, or
  search the payloads
- Live summary in the sidebar that follows your filters

**AI requests**
- Prompts and responses as a readable conversation, not escaped JSON — OpenAI,
  Anthropic, Bedrock, Gemini and Cohere
- Token usage and cost per request, including prompt-cache savings
- Which model was asked for versus which one actually served the call

**AI Gateway plugins** — each request shows what the gateway did to it
- **PII sanitizer** — the entities caught and what replaced them
- **Prompt compression** — original versus compressed, with tokens saved
- **Semantic cache** — hit or miss, and the spend avoided
- **LLM as judge** — the accuracy score and the judge's own exchange

**MCP and A2A**
- Tool calls with arguments and results, laid out rather than dumped
- Server tool catalogues, session tracking, and JSON-RPC errors
- Agent task state, conversation history and artifacts

**Sharing**
- Export selected requests, a filtered set, or a single log as JSON
- Credentials and captured PII redacted by default

## Getting started

### Build

```
docker build -t kong-log-viewer .
```

### Run

```
docker run -d \
  --name kong-log-viewer \
  -p 5015:5015 \
  -v kong_logs_data:/app/data \
  kong-log-viewer
```

Open <http://localhost:5015>.

### Send it your logs

Add the `http-log` plugin and point it at the viewer:

```
curl -X POST http://localhost:8001/plugins \
  --data name=http-log \
  --data config.http_endpoint=http://host.docker.internal:5015/logs
```

To see prompts and responses, AI Gateway needs to be logging payloads. On your
`ai-proxy` or `ai-proxy-advanced` plugin:

```
config.logging.log_statistics: true
config.logging.log_payloads:   true
```

Without `log_payloads` you still get models, tokens and cost — just no
conversation.

> Keep it on a trusted network. The logs contain full prompts and request
> headers, and there is no authentication on the UI.

## Using it

**Filtering.** The filter bar adapts to what you're looking at — pick LLM and
you get Provider and Model, pick MCP and you get Method and Tool. Every filter
lives in the URL, so any view can be shared with a colleague as a link.

**Request detail.** Click any row. The drawer shows only the sections that
apply: conversation, usage and cost, and whichever plugins ran. The raw payload
is always available at the bottom.

**Sidebar summary.** Headline numbers and breakdowns for whatever is currently
in view. Click any bar to filter by it — clicking `openai` filters to that
provider, clicking a tool name filters to that tool.

**Export.** Tick rows and use *Export selected*, or *Export filtered* for a
whole result set, or *Export* inside the drawer for a single request. Files load
straight into another instance, which makes them handy for sharing a
reproducible example.

## Managing the container

### Upgrading

Rebuild and replace the container. The volume is untouched, so existing logs
survive:

```
docker build -t kong-log-viewer .
docker stop kong-log-viewer && docker rm kong-log-viewer
docker run -d --name kong-log-viewer -p 5015:5015 -v kong_logs_data:/app/data kong-log-viewer
```

### Purging the logs

```
# Stop the container
docker stop kong-log-viewer

# Remove the container (does not remove the volume)
docker rm kong-log-viewer

# Remove the volume (this deletes all log data)
docker volume rm kong_logs_data
```

Then run the container again to start from an empty database.
