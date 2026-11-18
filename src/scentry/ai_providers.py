"""Who the ai service asks: Claude through Anthropic's API, a model on an Ollama server
(on this machine or your network), or a model behind any OpenAI-compatible chat API
(OpenAI, Gemini, OpenRouter, LM Studio, vLLM, llama.cpp's server).

Each gets the same system prompt and material, no tools, and must answer in the JSON
schema it is given; the answer is checked against it before anything is stored."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

import anthropic

from scentry.config import Settings

PROVIDERS = {"anthropic": "Anthropic", "ollama": "Ollama", "openai": "OpenAI-compatible"}
DEFAULT_MODEL = {"anthropic": "claude-opus-5-5"}
DEFAULT_URL = {"ollama": "http://host.docker.internal:11434",
               "openai": "https://api.openai.com/v1"}  # fmt: skip

MAX_TOKENS = 16000  # Claude: the answer and its thinking
OUTPUT_ROOM = 8192  # Ollama: context kept free for the answer (and a model's thinking)
CHARS_PER_TOKEN = 3  # a cautious guess, for code and English: more tokens, not fewer

# Server-side fallback: a request Claude's safety classifiers decline (security material
# can look like attack work) is answered by the model Anthropic picks for that case.
FALLBACK_BETA = "server-side-fallback-2026-07-01"
_FALLBACK_MODELS = ("claude-opus-5", "claude-fable-5", "claude-mythos-5", "claude-sonnet-5-5")


class AiError(Exception):
    """A request that can't be answered: shown on the note."""


class Retry(Exception):
    """The model couldn't be reached or was busy: try the same request again later."""


@dataclass(slots=True)
class Answer:
    result: dict[str, Any]
    model: str
    input_tokens: int
    output_tokens: int


class Provider(Protocol):
    name: str  # anthropic | ollama | openai
    model: str

    def ask(self, system: str, text: str, schema: dict) -> Answer: ...

    def check(self) -> str | None:
        """What's wrong with the setup, found without spending anything; None if fine."""
        ...


def label(model: str | None, provider: str | None = None) -> str:
    """Who wrote an answer, as the portal names it."""
    if provider == "anthropic" or (model or "").startswith("claude"):
        return "Claude"
    return model or "AI"


def make(settings: Settings, *, client=None, http=None) -> tuple[Provider | None, str]:
    """The provider the settings choose, or None and why AI explanations are off."""
    kind = settings.ai_provider
    model = settings.ai_model.strip() or DEFAULT_MODEL.get(kind, "")
    url = (settings.ai_base_url.strip() or DEFAULT_URL.get(kind, "")).rstrip("/")
    if kind == "anthropic":
        key = settings.anthropic_api_key.strip() or settings.ai_api_key.strip()
        if not key:
            return None, "no SCENTRY_ANTHROPIC_API_KEY"
        client = client or anthropic.Anthropic(api_key=key, timeout=float(settings.ai_timeout))
        return Claude(client, model), ""
    if not model:
        return None, f"SCENTRY_AI_PROVIDER={kind} needs SCENTRY_AI_MODEL"
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None, "SCENTRY_AI_BASE_URL isn't an http(s) address"
    http = http or Http(settings.ai_timeout)
    if kind == "ollama":
        return Ollama(url, model, settings.ai_context, http), ""
    return OpenAICompatible(url, model, settings.ai_api_key.strip(), http), ""


# --- answers ----------------------------------------------------------------------------


def _shape(value: Any, schema: dict) -> bool:
    if schema["type"] == "object":
        return (isinstance(value, dict) and set(value) == set(schema["required"])
                and all(_shape(value[k], s) for k, s in schema["properties"].items()))
    if schema["type"] == "array":
        return isinstance(value, list) and all(_shape(v, schema["items"]) for v in value)
    return isinstance(value, str) and ("enum" not in schema or value in schema["enum"])


_FENCED = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL)


def parse(text: str, schema: dict) -> dict[str, Any]:
    """The answer, if it is the JSON asked for. (Models that don't constrain their output
    sometimes wrap it in a Markdown code fence: that much is forgiven.)"""
    if m := _FENCED.match(text or ""):
        text = m[1]
    try:
        result = json.loads(text)
    except ValueError as e:
        raise AiError("The answer wasn't in the expected form.") from e
    if not _shape(result, schema):
        raise AiError("The answer wasn't in the expected form.")
    for key in ("priorities", "noise"):
        if key in result:
            result[key] = result[key][:5]
    return result


def _cut(text: object, limit: int = 300) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[:limit] + "…"


# --- Claude, through Anthropic's API ---------------------------------------------------


class Claude:
    name = "anthropic"

    def __init__(self, client, model: str):
        self.client, self.model = client, model

    def check(self) -> str | None:
        return None  # a wrong key shows on the first request

    def ask(self, system: str, text: str, schema: dict) -> Answer:
        extra: dict[str, Any] = {}
        if self.model.startswith(_FALLBACK_MODELS):
            extra = {"betas": [FALLBACK_BETA], "fallbacks": "default"}
        try:
            response = self.client.beta.messages.create(
                model=self.model,
                max_tokens=MAX_TOKENS,
                system=system,
                messages=[{"role": "user", "content": text}],
                output_config={"effort": "medium",
                               "format": {"type": "json_schema", "schema": schema}},  # fmt: skip
                **extra,
            )
        except (anthropic.RateLimitError, anthropic.InternalServerError,
                anthropic.APIConnectionError) as e:  # fmt: skip
            raise Retry(_api_message(e)) from e
        except anthropic.AuthenticationError as e:
            raise AiError("Anthropic refused the API key (SCENTRY_ANTHROPIC_API_KEY).") from e
        except anthropic.APIStatusError as e:
            if e.status_code >= 500:
                raise Retry(_api_message(e)) from e
            raise AiError(_api_message(e)) from e

        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None)
            raise AiError("Claude declined to answer" + (f" ({category})" if category else "")
                          + ".")  # fmt: skip
        if response.stop_reason == "max_tokens":
            raise AiError("The answer was cut off.")
        text_out = next((b.text for b in response.content if b.type == "text"), "")
        usage = response.usage
        return Answer(parse(text_out, schema), response.model, usage.input_tokens or 0,
                      usage.output_tokens or 0)  # fmt: skip


def _api_message(e: anthropic.APIError) -> str:
    status = getattr(e, "status_code", None)
    body = getattr(e, "body", None)
    message = body.get("error", {}).get("message") if isinstance(body, dict) else None
    text = message or e.__class__.__name__
    return _cut(f"{text} (HTTP {status})" if status else text)


# --- plain HTTP, for Ollama and OpenAI-compatible servers -------------------------------


@dataclass(slots=True)
class Reply:
    status: int
    data: Any  # the JSON body, or None


class Http:
    """One JSON request at a time, with the standard library. Unreachable -> Retry; no
    answer in time -> AiError (sending it again would only wait as long again)."""

    def __init__(self, timeout: int):
        self.timeout = timeout

    def __call__(self, method: str, url: str, body: dict | None = None,
                 headers: dict[str, str] | None = None,
                 timeout: int | None = None) -> Reply:  # fmt: skip
        data = json.dumps(body).encode() if body is not None else None
        # make() allows http(s) addresses only.
        req = urllib.request.Request(url, data=data, method=method,  # noqa: S310
                                     headers={"Content-Type": "application/json",
                                              **(headers or {})})  # fmt: skip
        wait = self.timeout if timeout is None else timeout
        try:
            with urllib.request.urlopen(req, timeout=wait) as res:  # noqa: S310
                return Reply(res.status, _json(res.read()))
        except urllib.error.HTTPError as e:
            return Reply(e.code, _json(e.read()))
        except TimeoutError as e:
            raise AiError(f"No answer within {wait} s (SCENTRY_AI_TIMEOUT).") from e
        except urllib.error.URLError as e:
            if isinstance(e.reason, TimeoutError):
                raise Retry(f"{urlsplit(url).netloc} didn't respond") from e
            raise Retry(f"Can't reach {urlsplit(url).netloc}: {_cut(e.reason, 200)}") from e
        except OSError as e:  # a connection dropped mid-answer
            raise Retry(f"{urlsplit(url).netloc}: {_cut(e, 200)}") from e


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except ValueError:
        return None


def _error_text(data: Any) -> str:
    """The message in an error body: Ollama's {"error": "..."}, OpenAI's {"error":
    {"message": "..."}}."""
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            err = err.get("message")
        if err:
            return _cut(err)
    return ""


# --- Ollama -----------------------------------------------------------------------------


class Ollama:
    """Ollama's own chat API, not its OpenAI-compatible one: only this one takes the
    context size (num_ctx) and can be told to refuse a prompt that doesn't fit rather than
    silently cut it."""

    name = "ollama"

    def __init__(self, url: str, model: str, context: int, http: Callable[..., Reply]):
        self.url, self.model, self.context, self.http = url, model, context, http

    def check(self) -> str | None:
        try:
            reply = self.http("GET", f"{self.url}/api/tags", timeout=10)
        except (Retry, AiError) as e:
            return str(e)
        names = {m.get("name") for m in (reply.data or {}).get("models") or []
                 if isinstance(m, dict)} if isinstance(reply.data, dict) else set()  # fmt: skip
        if reply.status != 200:
            return f"{self.url} doesn't look like Ollama (HTTP {reply.status})"
        wanted = self.model if ":" in self.model else f"{self.model}:latest"
        if wanted not in names:
            return f"Ollama has no model {self.model}: pull it with `ollama pull {self.model}`"
        return None

    def ask(self, system: str, text: str, schema: dict) -> Answer:
        guess = (len(system) + len(text)) // CHARS_PER_TOKEN
        if guess + OUTPUT_ROOM > self.context:
            raise AiError(f"Too much to send: about {guess} tokens, and the model's context "
                          f"is {self.context} (SCENTRY_AI_CONTEXT).")  # fmt: skip
        reply = self.http("POST", f"{self.url}/api/chat", {
            "model": self.model,
            "stream": False,
            "format": schema,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": text}],
            # Refuse what doesn't fit instead of quietly dropping part of the material.
            "truncate": False,
            "shift": False,
            "options": {"num_ctx": self.context, "temperature": 0},
        })  # fmt: skip
        data = reply.data if isinstance(reply.data, dict) else {}
        if reply.status == 404:
            raise AiError(f"Ollama has no model {self.model}: pull it with "
                          f"`ollama pull {self.model}`.")  # fmt: skip
        if reply.status == 400:
            raise AiError(f"Ollama: {_error_text(data) or 'bad request'} (SCENTRY_AI_CONTEXT "
                          "sets the context size).")  # fmt: skip
        if reply.status == 503:
            raise Retry("Ollama is busy")
        if reply.status != 200:
            raise AiError(f"Ollama: {_error_text(data) or f'HTTP {reply.status}'}")
        if data.get("done_reason") == "length":
            raise AiError("The answer was cut off: the model ran out of context "
                          "(SCENTRY_AI_CONTEXT).")  # fmt: skip
        content = (data.get("message") or {}).get("content", "")
        return Answer(parse(content, schema), data.get("model") or self.model,
                      data.get("prompt_eval_count") or 0, data.get("eval_count") or 0)  # fmt: skip


# --- OpenAI-compatible chat completions -------------------------------------------------


class OpenAICompatible:
    name = "openai"

    def __init__(self, url: str, model: str, key: str, http: Callable[..., Reply]):
        self.url, self.model, self.http = url, model, http
        self.headers = {"Authorization": f"Bearer {key}"} if key else {}

    def check(self) -> str | None:
        try:
            reply = self.http("GET", f"{self.url}/models", headers=self.headers, timeout=10)
        except (Retry, AiError) as e:
            return str(e)
        if reply.status in (401, 403):
            return "The server refused the API key (SCENTRY_AI_API_KEY)"
        listed = reply.data.get("data") if isinstance(reply.data, dict) else None
        if reply.status == 200 and isinstance(listed, list):
            ids = {m.get("id") for m in listed if isinstance(m, dict)}
            if ids and self.model not in ids:
                return f"The server doesn't list a model {self.model}"
        return None  # not every server lists its models: the first request will tell

    def ask(self, system: str, text: str, schema: dict) -> Answer:
        reply = self.http("POST", f"{self.url}/chat/completions", {
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": text}],
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": "answer", "strict": True,
                                                "schema": schema}},
        }, headers=self.headers)  # fmt: skip
        data = reply.data if isinstance(reply.data, dict) else {}
        why = _error_text(data)
        if reply.status in (401, 403):
            raise AiError("The server refused the API key (SCENTRY_AI_API_KEY).")
        if reply.status == 429 or reply.status >= 500:
            raise Retry(why or f"HTTP {reply.status}")
        if reply.status != 200:
            raise AiError(why or f"HTTP {reply.status}")
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        if message.get("refusal") or choice.get("finish_reason") == "content_filter":
            raise AiError(f"{self.model} declined to answer.")
        if choice.get("finish_reason") == "length":
            raise AiError("The answer was cut off.")
        usage = data.get("usage") or {}
        result = parse(message.get("content") or "", schema)
        return Answer(result, data.get("model") or self.model, usage.get("prompt_tokens") or 0,
                      usage.get("completion_tokens") or 0)  # fmt: skip
