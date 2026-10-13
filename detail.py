"""Turn a raw Kong http-log payload into the structured sections the detail
drawer renders.

Everything here is defensive: log shapes vary between Kong versions and between
AI plugins, and a missing block means "this plugin did not run", not an error.
Sections are omitted entirely when their plugin did not fire; within a section
every known field is emitted so the shape stays consistent.
"""

import json
import re


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _d(value):
    return value if isinstance(value, dict) else {}


def _num(value):
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _str(value):
    return value if isinstance(value, str) and value else None


def _header(headers, name):
    headers = _d(headers)
    target = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == target:
            return value[0] if isinstance(value, list) and value else value
    return None


def _parse(text):
    """Parse an escaped-JSON string field, returning None if it isn't JSON."""
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        return json.loads(stripped)
    except (ValueError, RecursionError):
        # RecursionError comes from deeply nested input and is not a ValueError.
        return None


def _content_to_text(content):
    """OpenAI content is a string, or a list of parts for multimodal calls."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                if part.get("type") == "text" and isinstance(part.get("text"), str):
                    parts.append(part["text"])
                elif part.get("type") in ("image_url", "image"):
                    parts.append("[image]")
                elif part.get("type") == "thinking" and isinstance(part.get("thinking"), str):
                    parts.append(part["thinking"])
                elif part.get("type") == "tool_use":
                    parts.append("[tool_use: " + str(part.get("name") or "?") + "]")
                elif part.get("type") == "tool_result":
                    parts.append("[tool_result]")
                elif isinstance(part.get("text"), str):
                    parts.append(part["text"])
        return "\n\n".join(parts)
    if content is None:
        return ""
    return json.dumps(content, indent=2)


# --------------------------------------------------------------------------
# Conversation
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Content segmentation
# --------------------------------------------------------------------------
#
# Agent frameworks routinely pack structure into a single message's content
# string: a JSON array of prior turns, tool results appended as text, or both.
# Rendering that raw is unreadable, so a content string is split into segments
# the UI can present properly. Plain prose falls through untouched.

MAX_SEGMENT_SCAN = 400_000   # don't scan pathologically large bodies
MAX_SEGMENTS = 40
# Span matching is O(n) per candidate opener, so a string of unmatched braces
# is O(n^2). Cap total characters examined and fall back to plain text.
MAX_SCAN_STEPS = 2_000_000

_TOOL_CALL_RE = re.compile(r"(?:^|\n)[ \t]*[-*\u2022][ \t]*([\w.\-/:]+)[ \t]*(?:->|=>|:)[ \t]*$")
_HEADING_RE = re.compile(r"^[ \t]*\[([^\]\n]{1,60})\][ \t]*$")


def _match_json_span(text, start, budget=None):
    """End index of a balanced JSON value starting at `start`, or None.

    `budget` is a one-element list of remaining characters to examine, shared
    across calls so a pathological input cannot burn unbounded time.
    """
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        if budget is not None:
            budget[0] -= 1
            if budget[0] <= 0:
                return None
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0:
                try:
                    json.loads(text[start:i + 1])
                except (ValueError, RecursionError):
                    return None
                return i + 1
    return None


def _as_messages(value):
    """A list of {role, content} dicts, or None if it isn't one."""
    if not isinstance(value, list) or not value:
        return None
    turns = []
    for item in value:
        if not isinstance(item, dict) or "role" not in item:
            return None
        if "content" not in item and "parts" not in item:
            return None
        content = item.get("content")
        if content is None:
            content = item.get("parts")
        turns.append({
            "role": _str(item.get("role")) or "user",
            "content": _content_to_text(content),
        })
    return turns


def _unwrap_tool_result(value):
    """MCP tool results wrap their payload in content[].text, which is itself
    usually JSON. Unwrap both layers so the actual data is what's shown."""
    if isinstance(value, dict) and isinstance(value.get("content"), list):
        texts = [part.get("text") for part in value["content"]
                 if isinstance(part, dict) and isinstance(part.get("text"), str)]
        joined = "\n\n".join(t for t in texts if t)
        if joined:
            inner = _parse(joined)
            return inner if inner is not None else joined
    return value


def segment_content(text):
    """Split a content string into renderable segments."""
    if not isinstance(text, str) or not text.strip():
        return [{"kind": "text", "text": text or ""}]

    stripped = text.strip()
    if len(text) > MAX_SEGMENT_SCAN:
        return [{"kind": "text", "text": text}]

    # Whole string is JSON: either a packed transcript or a single object.
    whole = _parse(stripped)
    if whole is not None:
        messages = _as_messages(whole)
        if messages:
            return [{"kind": "messages", "turns": messages}]
        return [{"kind": "json", "value": whole}]

    if "{" not in text and "[" not in text:
        return [{"kind": "text", "text": text}]

    segments = []
    cursor = 0
    index = 0
    length = len(text)
    budget = [MAX_SCAN_STEPS]

    def push_text(chunk):
        if not chunk.strip():
            return None
        heading = _HEADING_RE.match(chunk.strip())
        if heading and "\n" not in chunk.strip():
            segments.append({"kind": "heading", "text": heading.group(1)})
            return None
        segments.append({"kind": "text", "text": chunk.strip("\n")})
        return chunk

    while index < length and len(segments) < MAX_SEGMENTS:
        ch = text[index]
        if ch not in "{[":
            index += 1
            continue
        # A JSON object can only be followed by a key or a close, so skip the
        # obvious non-starters before paying for a full scan.
        if ch == "{":
            nxt = text[index + 1:index + 2].strip() or text[index + 1:index + 3].lstrip()[:1]
            if nxt not in ('"', "}", ""):
                index += 1
                continue
        end = _match_json_span(text, index, budget)
        if end is None:
            if budget[0] <= 0:
                return [{"kind": "text", "text": text}]
            index += 1
            continue

        lead = text[cursor:index]
        # "- tool.name -> " immediately before the JSON names the tool.
        tool_match = _TOOL_CALL_RE.search(lead)
        tool_name = None
        if tool_match:
            tool_name = tool_match.group(1)
            lead = lead[:tool_match.start()]
        push_text(lead)

        try:
            value = json.loads(text[index:end])
        except (ValueError, RecursionError):
            index = end
            continue
        messages = _as_messages(value)
        if messages and not tool_name:
            segments.append({"kind": "messages", "turns": messages})
        elif tool_name:
            segments.append({"kind": "tool_result", "name": tool_name,
                             "value": _unwrap_tool_result(value)})
        else:
            segments.append({"kind": "json", "value": value})

        cursor = index = end

    push_text(text[cursor:])

    if not segments:
        return [{"kind": "text", "text": text}]
    # Nothing structured was found -- keep it simple.
    if all(seg["kind"] == "text" for seg in segments):
        return [{"kind": "text", "text": text}]
    return segments


def _request_turns(req):
    """Messages from a request body, across the formats AI Gateway accepts."""
    turns = []
    if not isinstance(req, dict):
        return turns

    # Anthropic Messages puts the system prompt in its own top-level field
    # rather than in messages[], so it would otherwise be dropped.
    system = req.get("system")
    if isinstance(system, str) and system.strip():
        turns.append({"role": "system", "content": system, "side": "request"})
    elif isinstance(system, list):
        text = _content_to_text(system)
        if text:
            turns.append({"role": "system", "content": text, "side": "request"})

    # OpenAI / Anthropic: messages[]. Gemini: contents[] with parts[].
    messages = req.get("messages")
    if not isinstance(messages, list):
        messages = req.get("contents") if isinstance(req.get("contents"), list) else []

    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if content is None and isinstance(msg.get("parts"), list):
            content = msg["parts"]
        role = _str(msg.get("role")) or "user"
        turn = {"role": "assistant" if role == "model" else role,
                "content": _content_to_text(content), "side": "request"}
        if msg.get("tool_calls"):
            turn["tool_calls"] = msg["tool_calls"]
        turns.append(turn)

    # A bare prompt string (legacy completions).
    if not turns and isinstance(req.get("prompt"), str):
        turns.append({"role": "user", "content": req["prompt"], "side": "request"})
    return turns


def _response_turns(res):
    """Assistant turns from a response body.

    Providers do not agree on shape, and Kong logs whatever the provider
    returned when the route is in native (non-OpenAI) mode:
      OpenAI     choices[].message / choices[].text
      Anthropic  top-level role + content[]  (also Bedrock)
      Gemini     candidates[].content.parts[]
      Cohere     text / generations[]
    """
    turns = []
    if not isinstance(res, dict):
        return turns

    # OpenAI-compatible
    if isinstance(res.get("choices"), list):
        for choice in res["choices"]:
            if not isinstance(choice, dict):
                continue
            msg = _d(choice.get("message")) or _d(choice.get("delta"))
            content = msg.get("content")
            if content is None and isinstance(choice.get("text"), str):
                content = choice["text"]
            turn = {"role": _str(msg.get("role")) or "assistant",
                    "content": _content_to_text(content), "side": "response",
                    "finish_reason": _str(choice.get("finish_reason"))}
            if msg.get("tool_calls"):
                turn["tool_calls"] = msg["tool_calls"]
            if msg.get("refusal"):
                turn["refusal"] = msg["refusal"]
            turns.append(turn)
        return turns

    # Anthropic Messages, which is also what Bedrock returns for Claude.
    if res.get("type") == "message" or (res.get("role") and res.get("content") is not None):
        tool_calls = [b for b in (res.get("content") or [])
                      if isinstance(b, dict) and b.get("type") == "tool_use"]
        turn = {"role": _str(res.get("role")) or "assistant",
                "content": _content_to_text(res.get("content")),
                "side": "response",
                "finish_reason": _str(res.get("stop_reason"))}
        if tool_calls:
            turn["tool_calls"] = tool_calls
        turns.append(turn)
        return turns

    # Gemini
    if isinstance(res.get("candidates"), list):
        for cand in res["candidates"]:
            if not isinstance(cand, dict):
                continue
            content = _d(cand.get("content"))
            turns.append({
                "role": "assistant",
                "content": _content_to_text(content.get("parts")),
                "side": "response",
                "finish_reason": _str(cand.get("finishReason")),
            })
        return turns

    # Cohere and other single-field shapes
    if isinstance(res.get("text"), str):
        turns.append({"role": "assistant", "content": res["text"], "side": "response",
                      "finish_reason": _str(res.get("finish_reason"))})
    elif isinstance(res.get("generations"), list):
        for gen in res["generations"]:
            if isinstance(gen, dict) and isinstance(gen.get("text"), str):
                turns.append({"role": "assistant", "content": gen["text"],
                              "side": "response"})
    return turns


def build_conversation(payload_block):
    """Render request/response payloads as an ordered chat transcript.

    Returns {"requested_model", "turns": [...], "unparsed": {...}}.
    `requested_model` is the model named in the client's body -- often a Kong
    route alias like "pii-demo" rather than the model that actually ran.
    """
    block = _d(payload_block)
    req = _parse(block.get("request"))
    res = _parse(block.get("response"))

    turns = []
    unparsed = {}

    # If a body is present but yields no turns -- either it is not JSON, or it
    # is a provider shape not recognised here -- show it raw rather than
    # silently dropping it.
    request_turns = _request_turns(req)
    if request_turns:
        turns.extend(request_turns)
    elif block.get("request"):
        unparsed["request"] = block.get("request")

    response_turns = _response_turns(res)
    if response_turns:
        turns.extend(response_turns)
    elif block.get("response"):
        unparsed["response"] = block.get("response")

    for turn in turns:
        segments = segment_content(turn.get("content"))
        # Only carry segments when they add something over the plain string.
        if len(segments) > 1 or segments[0]["kind"] != "text":
            turn["segments"] = segments

    return {
        "requested_model": _str(req.get("model")) if isinstance(req, dict) else None,
        "streamed": bool(req.get("stream")) if isinstance(req, dict) else False,
        "turns": turns,
        "unparsed": unparsed,
        "response_body": res if isinstance(res, dict) else None,
    }


# --------------------------------------------------------------------------
# Usage
# --------------------------------------------------------------------------

def build_usage(block, cache, response_body=None):
    usage = _d(block.get("usage"))
    meta = _d(block.get("meta"))
    prompt_details = _d(usage.get("prompt_tokens_details"))
    raw = _d(response_body)
    raw_usage = _d(raw.get("usage")) or _d(raw.get("usageMetadata"))

    def pick(*names):
        """First present value across Kong's block then the provider's body."""
        for source, keys in ((usage, names[:1]), (raw_usage, names[1:])):
            for key in keys:
                value = _num(source.get(key))
                if value is not None:
                    return value
        return None

    prompt = pick("prompt_tokens", "input_tokens", "promptTokenCount")
    completion = pick("completion_tokens", "output_tokens", "candidatesTokenCount")
    total = pick("total_tokens", "totalTokenCount")
    if total is None and prompt is not None and completion is not None:
        total = prompt + completion

    cached = _num(prompt_details.get("cached_tokens"))
    if cached is None:
        cached = _num(raw_usage.get("cache_read_input_tokens"))
    cache_write = _num(raw_usage.get("cache_creation_input_tokens"))
    savings = _num(_d(cache).get("cost_savings"))

    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": total,
        "cached_tokens": cached,
        "cache_write_tokens": cache_write,
        "cost": _num(usage.get("cost")),
        # On a cache hit usage is all zeros and the real figure is the saving.
        "cost_savings": savings,
        "served_from_cache": _str(_d(cache).get("cache_status")) == "hit",
        "time_to_first_token": _num(usage.get("time_to_first_token")),
        "time_per_token": _num(usage.get("time_per_token")),
        "llm_latency": _num(meta.get("llm_latency")),
        "request_mode": _str(meta.get("request_mode")),
    }


# --------------------------------------------------------------------------
# Feature sections
# --------------------------------------------------------------------------

def build_sanitizer(block):
    """PII sanitizer. `original_text` holds the real value that was replaced,
    so it is flagged sensitive and the UI masks it until revealed."""
    items = []
    for item in block.get("sanitized_items") or []:
        if not isinstance(item, dict):
            continue
        items.append({
            "entity_type": _str(item.get("entity_type")) or "UNKNOWN",
            "count": _num(item.get("count")),
            "original_text": item.get("original_text"),
            "redact_text": item.get("redact_text"),
        })

    blocked = bool(_str(block.get("input_block_reason")) or _str(block.get("output_block_reason")))
    return {
        "mode": _str(block.get("mode")),
        "identified": _num(block.get("identified")),
        "sanitized": _num(block.get("sanitized")),
        "input_masked": bool(block.get("input_masked")),
        "output_masked": bool(block.get("output_masked")),
        "blocked": blocked,
        "block_reason": _str(block.get("input_block_reason")) or _str(block.get("output_block_reason")),
        "block_source": _str(block.get("input_block_source")) or _str(block.get("output_block_source")),
        "duration": _num(block.get("duration")),
        "input_latency": _num(block.get("input_processing_latency")),
        "output_latency": _num(block.get("output_processing_latency")),
        "items": items,
        "contains_sensitive": any(i.get("original_text") for i in items),
    }


def build_compressor(block):
    items = []
    total_before = total_after = total_saved = 0
    for item in block.get("compress_items") or []:
        if not isinstance(item, dict):
            continue
        before = _num(item.get("original_token_count")) or 0
        after = _num(item.get("compress_token_count")) or 0
        saved = _num(item.get("save_token_count")) or 0
        total_before += before
        total_after += after
        total_saved += saved
        items.append({
            "msg_id": _num(item.get("msg_id")),
            "original_text": item.get("original_text"),
            "compress_text": item.get("compress_text"),
            "original_token_count": before,
            "compress_token_count": after,
            "save_token_count": saved,
            "information": _str(item.get("information")),
        })

    first = (block.get("compress_items") or [{}])[0]
    first = first if isinstance(first, dict) else {}
    return {
        "model": _str(first.get("compressor_model")),
        "compress_type": _str(first.get("compress_type")),
        "compress_value": _num(first.get("compress_value")),
        "duration": _num(block.get("duration")),
        "tokens_before": total_before or None,
        "tokens_after": total_after or None,
        "tokens_saved": total_saved or None,
        "pct_saved": round(total_saved / total_before * 100, 1) if total_before else None,
        "items": items,
    }


def build_cache(cache, response_headers):
    status = _str(cache.get("cache_status")) or _str(_header(response_headers, "x-cache-status"))
    return {
        "status": status.lower() if status else None,
        "cost_savings": _num(cache.get("cost_savings")),
        "embeddings_provider": _str(cache.get("embeddings_provider")),
        "embeddings_model": _str(cache.get("embeddings_model")),
        "embeddings_tokens": _num(cache.get("embeddings_tokens")),
        "embeddings_latency": _num(cache.get("embeddings_latency")),
        "fetch_latency": _num(cache.get("fetch_latency")),
        "ttl": _num(_header(response_headers, "x-cache-ttl")),
        "cache_key": _str(_header(response_headers, "x-cache-key")),
    }


def build_judge(block, proxy_usage, response_headers):
    """The judge runs its own model, which is often a different provider from
    the call it is scoring, so it carries its own meta/usage/transcript."""
    meta = _d(block.get("meta"))
    usage = _d(block.get("usage"))

    score = _num(_d(proxy_usage).get("llm_accuracy"))
    if score is None:
        score = _num(_header(response_headers, "x-kong-llm-accuracy-score"))

    return {
        "score": score,
        "provider": _str(meta.get("provider_name")),
        "request_model": _str(meta.get("request_model")),
        "response_model": _str(meta.get("response_model")),
        "llm_latency": _num(meta.get("llm_latency")),
        "prompt_tokens": _num(usage.get("prompt_tokens")),
        "completion_tokens": _num(usage.get("completion_tokens")),
        "total_tokens": _num(usage.get("total_tokens")),
        "cost": _num(usage.get("cost")),
        "conversation": build_conversation(block.get("payload")),
    }


# --------------------------------------------------------------------------
# MCP and A2A
# --------------------------------------------------------------------------
#
# Both protocols log the same way: an `rpc` array where each entry carries the
# JSON-RPC request and response as escaped strings, plus protocol-specific
# metadata. MCP adds a session id and an authorization audit trail; A2A adds
# task/context ids and a task state.

def _rpc_common(entry):
    return {
        "id": entry.get("id"),
        "method": _str(entry.get("method")),
        "latency": _num(entry.get("latency")),
        "response_size": _num(entry.get("response_body_size")),
        "error": _str(entry.get("error")),
        "error_code": _num(entry.get("code")),
    }


def build_mcp(block):
    calls = []
    for entry in block.get("rpc") or []:
        if not isinstance(entry, dict):
            continue
        call = _rpc_common(entry)
        call["tool_name"] = _str(entry.get("tool_name"))

        payload = _d(entry.get("payload"))
        req = _parse(payload.get("request"))
        res = _parse(payload.get("response"))
        call["request"] = req
        call["response"] = res
        call["params"] = _d(req).get("params") if isinstance(req, dict) else None
        result = _d(res).get("result") if isinstance(res, dict) else None
        call["result"] = result

        # A JSON-RPC error can appear in the response even when Kong returns
        # 200, so surface it from either place.
        if isinstance(res, dict) and isinstance(res.get("error"), dict):
            call["error"] = call["error"] or _str(res["error"].get("message"))
            if call["error_code"] is None:
                call["error_code"] = _num(res["error"].get("code"))

        # Shape the result by method so the UI can render it meaningfully.
        if call["method"] == "tools/call" and isinstance(result, dict):
            texts = []
            for part in result.get("content") or []:
                if isinstance(part, dict) and part.get("type") == "text":
                    texts.append(part.get("text"))
            call["content"] = "\n\n".join(t for t in texts if t)
            call["is_error"] = bool(result.get("isError"))
        elif call["method"] in ("tools/list", "resources/list", "prompts/list",
                                "resources/templates/list") and isinstance(result, dict):
            for key in ("tools", "resources", "prompts", "resourceTemplates"):
                if isinstance(result.get(key), list):
                    call["catalogue_kind"] = key
                    call["catalogue"] = [i for i in result[key] if isinstance(i, dict)]
                    break
        elif call["method"] == "initialize":
            call["client_info"] = _d(_d(req).get("params")).get("clientInfo")
            call["server_info"] = _d(result).get("serverInfo")
            call["protocol_version"] = _str(_d(result).get("protocolVersion"))

        calls.append(call)

    audit = []
    for entry in block.get("audit") or []:
        if not isinstance(entry, dict):
            continue
        consumer = _d(entry.get("consumer"))
        audit.append({
            "primitive": _str(entry.get("primitive")),
            "primitive_name": _str(entry.get("primitive_name")),
            "action": _str(entry.get("action")),
            "scope": _str(entry.get("scope")),
            "consumer_name": _str(consumer.get("name")),
            "consumer_id": _str(consumer.get("id")),
            "consumer_identifier": _str(consumer.get("identifier")),
        })

    return {
        "session_id": _str(block.get("mcp_session_id")),
        "calls": calls,
        "audit": audit,
    }


def build_a2a(block):
    calls = []
    for entry in block.get("rpc") or []:
        if not isinstance(entry, dict):
            continue
        call = _rpc_common(entry)
        call["binding"] = _str(entry.get("binding"))
        call["task_id"] = _str(entry.get("task_id"))
        call["task_state"] = _str(entry.get("task_state"))
        call["context_id"] = _str(entry.get("context_id"))

        payload = _d(entry.get("payload"))
        req = _parse(payload.get("request"))
        res = _parse(payload.get("response"))
        result = _d(res).get("result") if isinstance(res, dict) else None
        call["request"] = req
        call["response"] = res
        call["result"] = result

        if isinstance(res, dict) and isinstance(res.get("error"), dict):
            call["error"] = call["error"] or _str(res["error"].get("message"))
            if call["error_code"] is None:
                call["error_code"] = _num(res["error"].get("code"))

        # The outbound message, then the task history, form one transcript.
        turns = []
        message = _d(_d(req).get("params")).get("message")
        if isinstance(message, dict):
            turns.append({
                "role": _str(message.get("role")) or "user",
                "content": _a2a_parts(message.get("parts")),
                "message_id": _str(message.get("messageId")),
            })
        for item in _d(result).get("history") or []:
            if not isinstance(item, dict):
                continue
            turn = {
                "role": _str(item.get("role")) or "agent",
                "content": _a2a_parts(item.get("parts")),
                "message_id": _str(item.get("messageId")),
            }
            # The request message usually reappears at the head of history.
            if turns and turn["message_id"] and turn["message_id"] == turns[0]["message_id"]:
                continue
            turns.append(turn)
        call["turns"] = turns

        artifacts = []
        for art in _d(result).get("artifacts") or []:
            if isinstance(art, dict):
                artifacts.append({
                    "name": _str(art.get("name")) or _str(art.get("artifactId")),
                    "content": _a2a_parts(art.get("parts")),
                })
        call["artifacts"] = artifacts

        status = _d(result).get("status")
        if isinstance(status, dict):
            call["state"] = _str(status.get("state")) or call["task_state"]
            call["state_timestamp"] = _str(status.get("timestamp"))

        calls.append(call)

    return {"calls": calls}


def _a2a_parts(parts):
    """A2A message content is a list of typed parts."""
    if not isinstance(parts, list):
        return ""
    out = []
    for part in parts:
        if isinstance(part, dict):
            if part.get("kind") == "text" and isinstance(part.get("text"), str):
                out.append(part["text"])
            elif isinstance(part.get("text"), str):
                out.append(part["text"])
            elif part.get("kind"):
                out.append("[" + str(part["kind"]) + "]")
        elif isinstance(part, str):
            out.append(part)
    return "\n\n".join(out)


# --------------------------------------------------------------------------
# Overview
# --------------------------------------------------------------------------

def build_overview(payload, block):
    req = _d(payload.get("request"))
    res = _d(payload.get("response"))
    lat = _d(payload.get("latencies"))
    meta = _d(block.get("meta"))

    # A semantic-cache hit never reaches an upstream, and Kong reports -1.
    proxy_latency = _num(lat.get("proxy"))
    if proxy_latency is not None and proxy_latency < 0:
        proxy_latency = None

    return {
        "method": _str(req.get("method")),
        "uri": _str(req.get("uri")) or _str(req.get("url")),
        "status": _num(res.get("status")),
        "upstream_status": _num(payload.get("upstream_status")),
        "request_id": _str(req.get("id")) or _str(_header(res.get("headers"), "x-kong-request-id")),
        "consumer": _str(_d(payload.get("consumer")).get("username")),
        "consumer_custom_id": _str(_d(payload.get("consumer")).get("custom_id")),
        "client_ip": _str(payload.get("client_ip")),
        "user_agent": _str(_header(_d(payload.get("request")).get("headers"), "user-agent")),
        "route": _str(_d(payload.get("route")).get("name")),
        "service": _str(_d(payload.get("service")).get("name")),
        "workspace": _str(payload.get("workspace_name")),
        "source": _str(payload.get("source")),
        "provider": _str(meta.get("provider_name")),
        "request_model": _str(meta.get("request_model")),
        "response_model": _str(meta.get("response_model")),
        "operation": _str(meta.get("operation_name")),
        "latency_total": _num(lat.get("request")),
        "latency_kong": _num(lat.get("kong")),
        "latency_proxy": proxy_latency,
        "latency_breakdown": {k: _num(v) for k, v in lat.items() if _num(v) is not None},
        "request_size": _num(req.get("size")),
        "response_size": _num(res.get("size")),
    }


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def build_detail(payload, ai_block, feature_block):
    """Assemble every section present in this payload.

    `ai_block` and `feature_block` are passed in from app.py so the alias
    matching lives in exactly one place.
    """
    if not isinstance(payload, dict):
        return {"sections": [], "overview": {}, "chips": []}

    ai = _d(payload.get("ai"))
    kind, block = ai_block(ai)
    cache = _d(block.get("cache"))
    res_headers = _d(_d(payload.get("response")).get("headers"))

    detail = {
        "kind": kind,
        "overview": build_overview(payload, block),
        "sections": [],
        "chips": [],
    }

    if block.get("payload"):
        conv = build_conversation(block.get("payload"))
        if conv["turns"] or conv["unparsed"]:
            detail["conversation"] = conv
            detail["sections"].append("conversation")

    if block.get("usage") or block.get("meta"):
        detail["usage"] = build_usage(
            block, cache, (detail.get("conversation") or {}).get("response_body"))
        detail["sections"].append("usage")

    sanitizer = feature_block(ai, "sanitizer")
    if sanitizer is not None:
        detail["sanitizer"] = build_sanitizer(sanitizer)
        detail["sections"].append("sanitizer")
        n = detail["sanitizer"]["sanitized"] or detail["sanitizer"]["identified"]
        detail["chips"].append({
            "kind": "sanitizer",
            "label": "PII " + (str(int(n)) if n else "0"),
            "tone": "warn" if detail["sanitizer"]["blocked"] else "info",
        })

    compressor = feature_block(ai, "compressor")
    if compressor is not None:
        detail["compressor"] = build_compressor(compressor)
        detail["sections"].append("compressor")
        saved = detail["compressor"]["tokens_saved"]
        detail["chips"].append({
            "kind": "compressor",
            "label": ("−%d tok" % saved) if saved else "compressed",
            "tone": "ok",
        })

    if cache:
        detail["cache"] = build_cache(cache, res_headers)
        detail["sections"].append("cache")
        status = detail["cache"]["status"]
        detail["chips"].append({
            "kind": "cache",
            "label": "CACHE " + (status.upper() if status else "?"),
            "tone": "ok" if status == "hit" else "muted",
        })

    judge = feature_block(ai, "judge")
    if judge is not None:
        detail["judge"] = build_judge(judge, block.get("usage"), res_headers)
        detail["sections"].append("judge")
        score = detail["judge"]["score"]
        detail["chips"].append({
            "kind": "judge",
            "label": "JUDGE " + (("%g" % score) if score is not None else "–"),
            "tone": "err" if (score is not None and score < 50) else "ok",
        })

    if kind == "mcp":
        mcp = build_mcp(block)
        if mcp["calls"] or mcp["audit"] or mcp["session_id"]:
            detail["mcp"] = mcp
            detail["sections"].append("mcp")
            for call in mcp["calls"]:
                if call.get("error"):
                    detail["chips"].append({
                        "kind": "rpc_error", "tone": "err",
                        "label": "RPC " + (str(int(call["error_code"])) if call.get("error_code") is not None else "ERROR"),
                    })
                elif call.get("tool_name"):
                    detail["chips"].append({"kind": "tool", "tone": "info",
                                            "label": call["tool_name"]})
                elif call.get("method"):
                    detail["chips"].append({"kind": "method", "tone": "muted",
                                            "label": call["method"]})
            for entry in mcp["audit"]:
                detail["chips"].append({
                    "kind": "audit",
                    "tone": "ok" if entry.get("action") == "allow" else "err",
                    "label": "AUDIT " + (entry.get("action") or "?").upper(),
                })

    if kind == "a2a":
        a2a = build_a2a(block)
        if a2a["calls"]:
            detail["a2a"] = a2a
            detail["sections"].append("a2a")
            for call in a2a["calls"]:
                if call.get("error"):
                    detail["chips"].append({"kind": "rpc_error", "tone": "err",
                                            "label": "RPC ERROR"})
                state = call.get("state") or call.get("task_state")
                if state:
                    detail["chips"].append({
                        "kind": "task", "tone": "ok" if state == "completed" else "warn",
                        "label": state.upper(),
                    })

    targets = block.get("tried_targets")
    if isinstance(targets, list) and targets:
        detail["targets"] = [t for t in targets if isinstance(t, dict)]
        detail["sections"].append("targets")

    return detail
