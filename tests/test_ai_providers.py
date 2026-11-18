"""Who answers AI explanations: Claude, Ollama, or an OpenAI-compatible server. Faked
here; test_ollama_for_real asks a real Ollama when SCENTRY_TEST_OLLAMA names one."""

from __future__ import annotations

import os
import socket
import threading

import pytest
from fastapi.testclient import TestClient

from scentry import ai, ai_providers, db
from scentry.ai_providers import AiError, Http, Ollama, OpenAICompatible, Reply, Retry
from scentry.config import Settings
from scentry.models import Finding, Scan, Target, utcnow

ANSWER = {"summary": "User input reaches a shell.", "real": "likely",
          "reason": "It goes to os.system.", "fix": "Use a list."}  # fmt: skip


def settings(**kw):
    return Settings(_env_file=None, database_url="sqlite://", admin_password="pw", **kw)


class FakeHttp:
    """Stands in for Http: records each request, answers from a queue of Replies."""

    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def __call__(self, method, url, body=None, headers=None, timeout=None):
        self.calls.append({"method": method, "url": url, "body": body, "headers": headers})
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def ollama_ok(content, **extra):
    return Reply(200, {"model": "qwen3:4b", "done_reason": "stop", "message": {
        "role": "assistant", "content": content}, "prompt_eval_count": 900,
        "eval_count": 80, **extra})  # fmt: skip


def openai_ok(content, finish="stop", **message):
    return Reply(200, {"model": "gpt-x", "usage": {"prompt_tokens": 700, "completion_tokens": 60},
                       "choices": [{"finish_reason": finish,
                                    "message": {"content": content, **message}}]})  # fmt: skip


def test_which_provider_the_settings_choose():
    p, off = ai_providers.make(settings())
    assert p is None and "ANTHROPIC_API_KEY" in off
    p, _ = ai_providers.make(settings(anthropic_api_key="sk-x"))
    assert (p.name, p.model) == ("anthropic", "claude-opus-5-5")

    p, off = ai_providers.make(settings(ai_provider="ollama"))
    assert p is None and "SCENTRY_AI_MODEL" in off  # no default model for Ollama
    p, _ = ai_providers.make(settings(ai_provider="ollama", ai_model="qwen3:4b"))
    assert (p.name, p.url, p.context) == ("ollama", "http://host.docker.internal:11434", 32768)
    p, _ = ai_providers.make(settings(ai_provider="openai", ai_model="gpt-x",
                                      ai_base_url="http://lmstudio.lan:1234/v1/"))  # fmt: skip
    assert (p.name, p.url, p.headers) == ("openai", "http://lmstudio.lan:1234/v1", {})
    p, _ = ai_providers.make(settings(ai_provider="openai", ai_model="gpt-x", ai_api_key="k"))
    assert p.url == "https://api.openai.com/v1" and p.headers == {"Authorization": "Bearer k"}
    p, off = ai_providers.make(settings(ai_provider="ollama", ai_model="m",
                                        ai_base_url="file:///etc/passwd"))  # fmt: skip
    assert p is None and "http(s)" in off

    assert ai_providers.label("claude-opus-5-5") == "Claude"
    assert ai_providers.label("qwen3:4b", "ollama") == "qwen3:4b"


def test_ollama_asks_with_the_schema_and_refuses_to_cut_the_material():
    http = FakeHttp(ollama_ok('{"summary": "User input reaches a shell.", "real": "likely", '
                              '"reason": "It goes to os.system.", "fix": "Use a list."}'))
    p = Ollama("http://o:11434", "qwen3:4b", 32768, http)
    answer = p.ask("system", "text", ai.FINDING_SCHEMA)
    assert (answer.result, answer.model, answer.input_tokens, answer.output_tokens) == (
        ANSWER, "qwen3:4b", 900, 80)  # fmt: skip
    sent = http.calls[0]
    assert sent["url"] == "http://o:11434/api/chat" and sent["body"]["format"] == ai.FINDING_SCHEMA
    assert sent["body"]["truncate"] is False and sent["body"]["shift"] is False
    assert sent["body"]["options"]["num_ctx"] == 32768 and "tools" not in sent["body"]
    assert [m["role"] for m in sent["body"]["messages"]] == ["system", "user"]


def test_ollama_errors():
    def ask(*replies, context=32768, text="text"):
        return Ollama("http://o:11434", "qwen3:4b", context, FakeHttp(*replies)).ask(
            "system", text, ai.FINDING_SCHEMA)  # fmt: skip

    with pytest.raises(AiError, match="ollama pull qwen3:4b"):
        ask(Reply(404, {"error": "model 'qwen3:4b' not found"}))
    with pytest.raises(AiError, match="exceeds the available context.*SCENTRY_AI_CONTEXT"):
        ask(Reply(400, {"error": "request (40000 tokens) exceeds the available context size"}))
    with pytest.raises(AiError, match="cut off"):
        ask(ollama_ok("{", done_reason="length"))
    with pytest.raises(AiError, match="expected form"):
        ask(ollama_ok('{"summary": "only this"}'))
    with pytest.raises(Retry):
        ask(Reply(503, {"error": "server busy"}))
    with pytest.raises(Retry, match="Can't reach"):
        ask(Retry("Can't reach o:11434: refused"))
    # Clearly too much for the context: not sent at all.
    with pytest.raises(AiError, match="Too much to send"):
        ask(context=9000, text="x" * 10_000)


def test_ollama_setup_check():
    tags = Reply(200, {"models": [{"name": "qwen3:4b"}, {"name": "gemma4:latest"}]})
    assert Ollama("http://o", "qwen3:4b", 1, FakeHttp(tags)).check() is None
    assert Ollama("http://o", "gemma4", 1, FakeHttp(tags)).check() is None  # :latest implied
    assert "ollama pull llama9" in Ollama("http://o", "llama9", 1, FakeHttp(tags)).check()
    assert "Can't reach" in Ollama("http://o", "m", 1, FakeHttp(Retry("Can't reach o"))).check()
    not_ollama = Ollama("http://o", "m", 1, FakeHttp(Reply(404, None)))
    assert "doesn't look like Ollama" in not_ollama.check()


def test_openai_compatible():
    fenced = '```json\n{"summary": "User input reaches a shell.", "real": "likely", ' \
             '"reason": "It goes to os.system.", "fix": "Use a list."}\n```'
    http = FakeHttp(openai_ok(fenced))
    p = OpenAICompatible("http://lm:1234/v1", "gpt-x", "k", http)
    answer = p.ask("system", "text", ai.FINDING_SCHEMA)
    assert answer.result == ANSWER and (answer.input_tokens, answer.output_tokens) == (700, 60)
    sent = http.calls[0]
    assert sent["url"] == "http://lm:1234/v1/chat/completions"
    assert sent["headers"] == {"Authorization": "Bearer k"}
    fmt = sent["body"]["response_format"]
    assert fmt["type"] == "json_schema" and fmt["json_schema"]["schema"] == ai.FINDING_SCHEMA
    assert fmt["json_schema"]["strict"] is True and "tools" not in sent["body"]

    def ask(*replies):
        return OpenAICompatible("http://lm/v1", "gpt-x", "", FakeHttp(*replies)).ask(
            "s", "t", ai.FINDING_SCHEMA)  # fmt: skip

    with pytest.raises(AiError, match="declined"):
        ask(openai_ok(None, refusal="I can't help with that."))
    with pytest.raises(AiError, match="cut off"):
        ask(openai_ok("{", finish="length"))
    with pytest.raises(AiError, match="refused the API key"):
        ask(Reply(401, {"error": {"message": "bad key"}}))
    with pytest.raises(AiError, match="no such model"):
        ask(Reply(404, {"error": {"message": "no such model"}}))
    with pytest.raises(Retry, match="slow down"):
        ask(Reply(429, {"error": {"message": "slow down"}}))

    listing = Reply(200, {"data": [{"id": "gpt-x"}]})
    assert OpenAICompatible("http://lm/v1", "gpt-x", "", FakeHttp(listing)).check() is None
    assert "doesn't list" in OpenAICompatible("http://lm/v1", "other", "",
                                              FakeHttp(listing)).check()  # fmt: skip
    # Not every server lists its models: that's no reason to complain.
    assert OpenAICompatible("http://lm/v1", "m", "", FakeHttp(Reply(404, None))).check() is None


def test_http_unreachable_is_retried_and_silence_is_an_error():
    with socket.socket() as s:  # a port nothing listens on
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with pytest.raises(Retry, match="Can't reach"):
        Http(5)("GET", f"http://127.0.0.1:{port}/api/tags")

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    accepted = []
    threading.Thread(target=lambda: accepted.append(server.accept()), daemon=True).start()
    try:
        with pytest.raises(AiError, match="No answer within 1 s"):
            Http(1)("POST", f"http://127.0.0.1:{server.getsockname()[1]}/api/chat", {"x": 1})
    finally:
        for conn, _ in accepted:
            conn.close()
        server.close()


def test_a_slow_model_is_not_taken_for_an_interrupted_one(tmp_path):
    s = settings(ai_timeout=3600)
    s = s.model_copy(update={"database_url": f"sqlite:///{tmp_path / 'p.db'}"})
    db.configure(s.database_url)
    with db.SessionLocal() as session:
        t = Target(name="app", profile="owned", source="https://git.example/me/app.git")
        session.add(t)
        session.flush()
        f = Finding(target_id=t.id, fingerprint="x", scanner="semgrep", rule_id="r",
                    title="Shell injection", severity="high")  # fmt: skip
        session.add(f)
        session.commit()
        note = ai.request(session, "finding", f.id, t.id, "admin")
        note.status, note.started_at = "running", utcnow()
        session.commit()
        later = utcnow() + ai.STUCK + ai.STUCK  # 30 minutes: still within its hour
        p = Ollama("http://o", "qwen3:4b", 32768, FakeHttp())
        assert ai.run_once(session, p, s, later) == "idle"
        assert note.status == "running"


def test_the_portal_names_the_model(tmp_path):
    from scentry.web.app import create_app

    s = settings().model_copy(update={"database_url": f"sqlite:///{tmp_path / 'w.db'}"})
    client = TestClient(create_app(s), follow_redirects=False)
    with db.SessionLocal() as session:
        t = Target(name="app", profile="owned", source="https://git.example/me/app.git")
        session.add(t)
        session.flush()
        scan = Scan(target_id=t.id, status="done", score=80, verdict="B", complete=True)
        session.add(scan)
        session.flush()
        session.add(Finding(target_id=t.id, fingerprint="x", scanner="semgrep", rule_id="r",
                            title="Shell injection", severity="high",
                            last_seen_scan_id=scan.id))  # fmt: skip
        state = ai.state_row(session)
        state.configured, state.provider, state.model, state.seen_at = (
            True, "ollama", "qwen3:4b", utcnow())  # fmt: skip
        session.commit()
    auth = ("admin", "pw")
    page = client.get("/findings/1", auth=auth).text
    assert "Explain with qwen3:4b" in page and "Claude" not in page
    system = client.get("/system", auth=auth).text
    assert "qwen3:4b · Ollama" in system and "easier to mislead" in system
    client.post("/findings/1/explain", auth=auth)
    assert "qwen3:4b is answering" in client.get("/findings/1", auth=auth).text


@pytest.mark.skipif(not os.environ.get("SCENTRY_TEST_OLLAMA"),
                    reason="set SCENTRY_TEST_OLLAMA=<url>|<model> to ask a real Ollama")
def test_ollama_for_real():
    url, _, model = os.environ["SCENTRY_TEST_OLLAMA"].partition("|")
    p = Ollama(url, model, 16384, Http(600))
    assert p.check() is None
    text = ("<material>\nFinding: [high] Shell injection\nLocation: app.py:3\n"
            "Evidence (from the scanned code):\nos.system('ping ' + request.args['host'])\n"
            "</material>\n\n" + ai.FINDING_ASK["owned"] + "\n" + ai.FINDING_FIELDS)
    answer = p.ask(ai.SYSTEM, text, ai.FINDING_SCHEMA)
    assert answer.result["real"] in ("likely", "unlikely", "unclear") and answer.output_tokens
    # More than fits, but not by Scentry's estimate (emoji are several tokens each):
    # Ollama itself must refuse it, not quietly cut it and answer.
    with pytest.raises(AiError, match="exceeds|longer than"):
        p.ask(ai.SYSTEM, "🦀" * 20_000, ai.FINDING_SCHEMA)
    with pytest.raises(AiError, match="pull"):
        Ollama(url, "no-such-model:1b", 8192, Http(60)).ask("s", "t", ai.FINDING_SCHEMA)
