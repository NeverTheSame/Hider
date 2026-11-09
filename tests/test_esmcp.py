"""The MCP server inside the bridge, against the stub Kibana. No cluster, no
model, invented values.

Three groups, following the design's measurement table: the protocol and
the tools (label round trip, refusals without values), the transport
(risk 11: token, loopback, Host, no CORS), and credential isolation (what
Claude Code is handed: argv, environment, working directory, tool list).
"""

from __future__ import annotations

import http.client
import json
import re
import shutil
import stat
import tempfile
import threading
from pathlib import Path

import pytest

from hider import elastic, esbridge, esmcp, eseval

CFG0 = elastic.load(elastic.EXAMPLE)
COOKIE = "sid=synthetic"


@pytest.fixture(scope="module")
def fixture():
    return eseval.generate(docs=150)


@pytest.fixture
def stub(fixture):
    kb = eseval.StubKibana(eseval.StubEngine(fixture, CFG0.indices), cookie=COOKIE).start()
    yield kb
    kb.stop()


@pytest.fixture
def short_dir():
    """A socket path must fit in 104 bytes; pytest's tmp_path on macOS does not."""
    d = tempfile.mkdtemp(prefix="hm-", dir="/tmp")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


def _config(url: str, profile: Path, **extra) -> elastic.ElasticConfig:
    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"stub": {"kibana": url}}
    raw["profile_dir"] = str(profile)
    raw.update(extra)
    return elastic.parse(raw, source="test")


class _Bridge:
    """A broker on a thread, as es-login leaves one running."""

    def __init__(self, cfg, sessions):
        esbridge.prepare_profile_dir(cfg.profile_dir)
        self.sock = esbridge.broker_socket(cfg.profile_dir)
        self.broker = esbridge.Broker(cfg, lambda: esbridge.UrllibTransport(COOKIE),
                                      poll_interval=0.01, sessions_dir=sessions)
        self.thread = threading.Thread(target=self.broker.serve, args=(self.sock,), daemon=True)
        self.thread.start()
        for _ in range(200):
            if esbridge.broker_running(self.sock):
                break
            threading.Event().wait(0.02)

    def call(self, op, **kw):
        return esbridge.BrokerClient(self.sock, timeout=30).call(op, **kw)

    def open(self, case="c1", terms=(), **kw):
        return self.call("open_case", case=case, terms=list(terms), tier2="none", **kw)

    def stop(self):
        if self.thread.is_alive():
            try:
                self.call("stop")
            except elastic.Refused:
                pass
            self.thread.join(10)


@pytest.fixture
def bridge(stub, short_dir):
    b = _Bridge(_config(stub.url, short_dir / "profile"), short_dir / "cases")
    b.sessions = short_dir / "cases"
    yield b
    b.stop()


class Mcp:
    """A minimal MCP client over the raw HTTP, so every byte that would reach
    Claude Code is visible to the test."""

    def __init__(self, url: str, token: str | None):
        u = re.match(r"http://127\.0\.0\.1:(\d+)(/.*)", url)
        self.port, self.path, self.token = int(u.group(1)), u.group(2), token
        self.bodies: list[bytes] = []
        self._id = 0

    def raw(self, method="POST", body: bytes | None = b"{}", *, path=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        h.update(headers or {})
        conn.request(method, path or self.path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        self.bodies.append(data)
        return r.status, dict(r.getheaders()), data

    def rpc(self, method, params=None, *, notify=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self._id += 1
            msg["id"] = self._id
        status, _, data = self.raw(body=json.dumps(msg).encode())
        if notify:
            return status
        assert status == 200, (status, data)
        return json.loads(data)

    def tool(self, name, **args):
        reply = self.rpc("tools/call", {"name": name, "arguments": args})
        res = reply["result"]
        text = res["content"][0]["text"]
        return (json.loads(text) if not res["isError"] else text), res["isError"]


def _no_truth(blobs, fixture):
    seen = b"\n".join(blobs).decode("utf-8")
    return [v for v in fixture.truth if len(v) > 4 and v in seen]


def _expected(fixture, index, pred):
    return sum(1 for d in fixture.docs if d.index == index and pred(eseval.flatten(d.source)))


# -- the protocol and the tools ----------------------------------------------


def test_a_session_investigates_with_labels_and_never_sees_a_value(bridge, fixture):
    tenant = fixture.tenants[0].name
    opened = bridge.open(terms=[tenant])
    (label, etype), = opened["seeded"]
    assert etype == "ORG_NAME" and tenant not in json.dumps(opened)
    c = Mcp(opened["url"], opened["token"])

    init = c.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "test", "version": "0"}})["result"]
    assert init["protocolVersion"] == "2025-06-18"
    assert init["serverInfo"]["name"] == esmcp.SERVER_NAME and "tools" in init["capabilities"]
    assert c.rpc("notifications/initialized", notify=True) == 202
    assert [t["name"] for t in c.rpc("tools/list")["result"]["tools"]] == list(esmcp.TOOLS)

    schema, err = c.tool("es_schema")
    assert not err and schema["case"]["seeded"] == [label]
    assert schema["case"]["labels"][label] == "ORG_NAME"
    assert schema["fields"]["labels.tenant_name"] == "identifier"

    # the label goes out, the real value is what Kibana is asked for
    by_tenant = [{"field": "labels.tenant_name", "op": "eq", "value": label}]
    want = _expected(fixture, "logs-app-*", lambda f: f.get("labels.tenant_name") == tenant)
    assert want > 0
    count, err = c.tool("es_count", index="logs-app-*", filters=by_tenant)
    assert not err and count["hits_total"]["value"] == want and "hits" not in count

    page, err = c.tool("es_search", index="logs-app-*", filters=by_tenant, size=5)
    assert not err and page["hits_shown"] == 5
    assert {h["_source"]["labels"]["tenant_name"] for h in page["hits"]} == {label}

    aggs, err = c.tool("es_aggregate", index="logs-app-*",
                       aggs={"servers": {"type": "terms", "field": "agent.name", "size": 5}})
    assert not err and "hits" not in aggs
    keys = [b["key"] for b in aggs["aggregations"]["servers"]["buckets"]]
    assert keys and all(re.fullmatch(r"ctr-[a-z]+-s\d+", k) for k in keys)

    # a server label learnt from the aggregation filters the next call
    narrowed, err = c.tool("es_count", index="logs-app-*",
                           filters=[{"field": "agent.name", "op": "eq", "value": keys[0]}])
    assert not err and narrowed["hits_total"]["value"] == \
        aggs["aggregations"]["servers"]["buckets"][0]["doc_count"]

    assert _no_truth(c.bodies, fixture) == []
    # the broker's own socket keeps working beside the MCP listener
    assert bridge.call("ping")["clusters"] == ["stub"]


@pytest.mark.parametrize("tool,args,code", [
    ("es_search", {"index": "logs-app-*", "filters": [
        {"field": "message", "op": "phrase", "value": "fail*"}]}, "pattern_query"),
    ("es_search", {"index": "logs-app-*", "sort": [{"field": "agent.name"}]}, "sort_identifier"),
    ("es_count", {"index": "logs-app-*", "filters": [
        {"field": "labels.tenant_name", "op": "eq", "value": "<Org-77>"}]}, "unknown_label"),
    ("es_count", {"index": "logs-*"}, "bad_index"),
    ("es_count", {"index": "logs-app-*", "query": {"match_all": {}}}, "bad_request"),
    ("es_count", {"index": "logs-app-*", "size": 50}, "bad_request"),
    ("es_search", {"index": "logs-app-*", "aggs": {}}, "bad_request"),
    ("es_aggregate", {"index": "logs-app-*"}, "bad_agg"),
    ("es_search", {"index": "logs-app-*", "terms": ["Contoso Group"]}, "bad_request"),
    ("es_search", {"index": "logs-app-*", "log": "/tmp/x.jsonl"}, "bad_request"),
    ("es_count", {"cluster": "elsewhere", "index": "logs-app-*"}, "bad_cluster"),
    ("es_schema", {"cluster": "stub"}, "bad_request"),
])
def test_refusals_are_tool_errors_with_a_code(bridge, tool, args, code):
    opened = bridge.open()
    text, err = Mcp(opened["url"], opened["token"]).tool(tool, **args)
    assert err and text.startswith(f"refused ({code}): ")


def test_a_real_value_typed_by_claude_is_refused_and_not_echoed(bridge, fixture):
    tenant = fixture.tenants[0].name
    opened = bridge.open(terms=[tenant])
    c = Mcp(opened["url"], opened["token"])
    for filt, code in [
        ({"field": "labels.tenant_name", "op": "eq", "value": tenant}, "literal_identifier"),
        ({"field": "message", "op": "phrase", "value": f"{tenant} failed"}, "known_value"),
    ]:
        text, err = c.tool("es_count", index="logs-app-*", filters=[filt])
        assert err and f"({code})" in text and tenant not in text


def test_a_failing_transport_is_bridge_error_with_nothing_in_it(stub, short_dir):
    class Exploding(esbridge.UrllibTransport):
        def request(self, *a, **k):
            raise KeyError("Contoso Group at " + stub.url)

    cfg = _config(stub.url, short_dir / "profile")
    b = _Bridge(cfg, short_dir / "cases")
    b.broker._factory = lambda: Exploding(COOKIE)
    try:
        opened = b.open()
        text, err = Mcp(opened["url"], opened["token"]).tool("es_count", index="logs-app-*")
        assert err and text.startswith("refused (bridge_error): ")
        assert "Contoso" not in text and "127.0.0.1" not in text
    finally:
        b.stop()


def test_protocol_edges():
    case = None  # none of these reach a tool
    h = esmcp.handle_message
    assert h(CFG0, case, [{"jsonrpc": "2.0", "id": 1, "method": "ping"}])["error"]["code"] == -32600
    assert h(CFG0, case, {"id": 1, "method": "ping"})["error"]["code"] == -32600
    assert h(CFG0, case, {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert h(CFG0, case, {"jsonrpc": "2.0", "id": 3, "result": {}}) is None
    assert h(CFG0, case, {"jsonrpc": "2.0", "id": 4, "method": "ping"})["result"] == {}
    v = h(CFG0, case, {"jsonrpc": "2.0", "id": 5, "method": "initialize",
                       "params": {"protocolVersion": "1999-01-01"}})["result"]["protocolVersion"]
    assert v == esmcp.PROTOCOL_VERSIONS[0]
    for method in ("login", "open_case", "stop", "resources/list", "prompts/get"):
        assert h(CFG0, case, {"jsonrpc": "2.0", "id": 6, "method": method})["error"]["code"] == -32601
    unknown = h(CFG0, case, {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                             "params": {"name": "es_unmask", "arguments": {}}})
    assert unknown["error"]["code"] == -32602


def test_the_decision_log_names_the_tool_and_holds_no_values(bridge, fixture):
    tenant = fixture.tenants[1].name
    opened = bridge.open(case="logged", terms=[tenant])
    label = opened["seeded"][0][0]
    c = Mcp(opened["url"], opened["token"])
    c.tool("es_count", index="logs-app-*",
           filters=[{"field": "labels.tenant_name", "op": "eq", "value": label}])
    c.tool("es_search", index="logs-app-*", size=3,
           filters=[{"field": "message", "op": "phrase", "value": f"{label} failed"}])
    c.tool("es_count", index="logs-*")
    rows = [json.loads(line) for line in
            (bridge.sessions / "logged" / "decisions.jsonl").read_text().splitlines()]
    # the case's job-name vocabulary is logged before its first page: a count, no name
    assert rows[0]["vocabulary"] == "names" and rows[0]["fields"]["job.name"] > 0 \
        and "tool" not in rows[0]
    rows = rows[1:]
    assert [r.get("tool") for r in rows] == ["es_count", "es_search", "es_count"]
    assert rows[0]["labels_used"] == [label] and rows[2]["refused"] == "bad_index"
    text = json.dumps(rows)
    assert [v for v in fixture.truth if len(v) > 4 and v in text] == []


# -- the transport: risk 11 ----------------------------------------------------


def test_the_listener_is_loopback_only():
    assert esmcp._loopback("127.0.0.1") and esmcp._loopback("::1")
    assert not esmcp._loopback("10.0.0.5") and not esmcp._loopback("0.0.0.0")
    assert not esmcp._loopback("localhost.evil.example")
    assert esmcp._loopback_origin("http://127.0.0.1:8790")
    assert esmcp._loopback_origin("http://localhost:3000")
    assert not esmcp._loopback_origin("https://evil.example")
    assert not esmcp._loopback_origin("null")


def test_requests_without_a_live_token_or_from_a_page_are_refused(bridge):
    opened = bridge.open()
    good = Mcp(opened["url"], opened["token"])
    assert bridge.broker.mcp.server_address[0] == "127.0.0.1"
    ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
    port = good.port
    cases = [
        (Mcp(opened["url"], None).raw(body=ping), 401),
        (Mcp(opened["url"], "x" * 43).raw(body=ping), 401),
        (good.raw(body=ping, headers={"Authorization": "Basic " + opened["token"]}), 401),
        (good.raw(body=ping, headers={"Host": f"evil.example:{port}"}), 403),   # DNS rebinding
        (good.raw(body=ping, headers={"Host": "127.0.0.1"}), 403),
        (good.raw(body=ping, headers={"Origin": "https://evil.example"}), 403),
        (good.raw("GET", None), 405),
        (good.raw("DELETE", None), 405),
        (good.raw("OPTIONS", None, headers={"Origin": "https://evil.example",
                                            "Access-Control-Request-Method": "POST"}), 405),
        (good.raw(body=ping, path="/"), 404),
        (good.raw(body=ping, headers={"Content-Type": "text/plain"}), 415),
        # refused on the declared length, before a byte of the body is read
        (good.raw(body=ping, headers={"Content-Length": str(esmcp._MAX_BODY + 1)}), 413),
        (good.raw(body=b"{not json"), 400),
    ]
    for (status, headers, body), want in cases:
        assert status == want, (want, status, body)
        assert not any(k.lower().startswith("access-control") for k in headers)
        assert opened["token"] not in body.decode()
    # the 401 says nothing about which case, or whether there is one
    assert json.loads(cases[0][0][2]) == {"error": "no open case for this token"}
    # a loopback Origin and localhost as Host are fine
    status, _, _ = good.raw(body=ping, headers={"Origin": "http://localhost:1234",
                                                "Host": f"localhost:{port}"})
    assert status == 200
    assert bridge.broker.mcp.denied[401] == 3 and bridge.broker.mcp.denied[403] == 3


def test_closing_or_reopening_a_case_kills_its_token(bridge, fixture):
    tenant = fixture.tenants[0].name
    first = bridge.open(terms=[tenant])
    c1 = Mcp(first["url"], first["token"])
    assert not c1.tool("es_count", index="logs-app-*")[1]
    second = bridge.open(terms=[tenant])  # the same case again: one session per case
    assert second["replaced"] is True and second["seeded"] == first["seeded"]
    assert c1.raw(body=b'{"jsonrpc":"2.0","id":1,"method":"ping"}')[0] == 401
    c2 = Mcp(second["url"], second["token"])
    assert not c2.tool("es_count", index="logs-app-*")[1]
    assert bridge.call("close_case", token=second["token"])["closed"] is True
    assert c2.raw(body=b'{"jsonrpc":"2.0","id":1,"method":"ping"}')[0] == 401
    assert bridge.call("close_case", token=second["token"])["closed"] is False


def test_a_case_keeps_its_labels_across_a_bridge_restart(stub, short_dir, fixture):
    cfg = _config(stub.url, short_dir / "profile")
    tenant = fixture.tenants[2].name
    b = _Bridge(cfg, short_dir / "cases")
    try:
        opened = b.open(case="kept", terms=[tenant])
        c = Mcp(opened["url"], opened["token"])
        aggs, _ = c.tool("es_aggregate", index="logs-app-*",
                         aggs={"servers": {"type": "terms", "field": "agent.name", "size": 3}})
        server = aggs["aggregations"]["servers"]["buckets"][0]
    finally:
        b.stop()
    d = short_dir / "cases" / "kept"
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert stat.S_IMODE((d / "session.json").stat().st_mode) == 0o600
    b = _Bridge(cfg, short_dir / "cases")
    try:
        again = b.open(case="kept")  # no terms: the vault comes back from disk
        c = Mcp(again["url"], again["token"])
        schema, _ = c.tool("es_schema")
        assert opened["seeded"][0][0] in schema["case"]["labels"]
        # a label from the last session still filters, to the same documents
        n, err = c.tool("es_count", index="logs-app-*",
                        filters=[{"field": "agent.name", "op": "eq", "value": server["key"]}])
        assert not err and n["hits_total"]["value"] == server["doc_count"]
    finally:
        b.stop()


def test_two_cases_have_two_vaults(bridge, fixture):
    a = bridge.open(case="a", terms=[fixture.tenants[0].name])
    b = bridge.open(case="b")
    label = a["seeded"][0][0]
    filt = [{"field": "labels.tenant_name", "op": "eq", "value": label}]
    assert not Mcp(a["url"], a["token"]).tool("es_count", index="logs-app-*", filters=filt)[1]
    text, err = Mcp(b["url"], b["token"]).tool("es_count", index="logs-app-*", filters=filt)
    assert err and "(unknown_label)" in text


def test_open_case_refuses_bad_names_and_typed_seeds_outside_the_site_map(bridge):
    for name in ("", "../etc", "a/b", ".hidden", "x" * 65, None):
        with pytest.raises(elastic.Refused) as e:
            bridge.open(case=name)
        assert e.value.code == "bad_request"
    with pytest.raises(elastic.Refused) as e:
        bridge.open(terms=["PASSWORD=hunter2"])
    assert e.value.code == "bad_request" and "hunter2" not in e.value.message


def test_stopping_the_bridge_ends_every_session(bridge):
    opened = bridge.open()
    c = Mcp(opened["url"], opened["token"])
    assert not c.tool("es_count", index="logs-app-*")[1]
    bridge.stop()
    with pytest.raises(OSError):
        c.raw(body=b'{"jsonrpc":"2.0","id":1,"method":"ping"}')


# -- credential isolation: what Claude Code is handed ----------------------------


def test_the_environment_is_an_allowlist(monkeypatch):
    base = {
        "HOME": "/Users/analyst", "PATH": "/usr/bin", "LANG": "en_GB.UTF-8", "LC_ALL": "C",
        "ANTHROPIC_API_KEY": "synthetic-key", "CLAUDE_CODE_USE_BEDROCK": "0",
        "HTTPS_PROXY": "http://proxy.example:3128", "NO_PROXY": ".corp.example",
        # everything below must not reach Claude Code
        "HIDER_ELASTIC": "/Users/analyst/site/elastic.json", "HIDER_VAULT_KEY": "k",
        "HIDER_PROFILE": "/p.json", "KIBANA_SID": "sid=abc", "ELASTIC_PASSWORD": "pw",
        "ES_API_KEY": "id:key", "AWS_SECRET_ACCESS_KEY": "s", "PYTHONPATH": "/repo",
        "VIRTUAL_ENV": "/repo/.venv", "OLDPWD": "/repo", "PWD": "/repo",
    }
    env = esmcp.claude_env(base)
    assert set(env) == {"HOME", "PATH", "LANG", "LC_ALL", "ANTHROPIC_API_KEY",
                        "CLAUDE_CODE_USE_BEDROCK", "HTTPS_PROXY", "NO_PROXY", "no_proxy"}
    assert env["NO_PROXY"] == ".corp.example,127.0.0.1,localhost"
    assert env["no_proxy"] == "127.0.0.1,localhost"
    assert not any(re.search(r"HIDER|ELASTIC|KIBANA|^ES_", k) for k in env)
    assert "NO_PROXY" not in esmcp.claude_env({"PATH": "/usr/bin"})


def test_argv_names_only_the_bridge_tools_and_holds_no_secret(tmp_path):
    launch = esmcp.prepare_launch("http://127.0.0.1:5555/mcp", "t" * 43)
    try:
        argv = esmcp.claude_argv(launch.mcp_config, "why <Org-01>?", model="haiku")
        assert argv[0] == "claude"
        for flag in ("--restricted", "--strict-mcp-config", "--no-session-persistence"):
            assert flag in argv
        assert argv[argv.index("--tools") + 1] == ""  # no built-in tool at all
        assert argv[argv.index("--allowedTools") + 1].split(",") == list(esmcp.ALLOWED_TOOLS)
        assert argv[argv.index("--mcp-config") + 1] == str(launch.mcp_config)
        joined = "\n".join(argv)
        assert "t" * 43 not in joined and "127.0.0.1" not in joined and "5555" not in joined
        interactive = esmcp.claude_argv(launch.mcp_config)
        assert "-p" not in interactive and "--restricted" in interactive

        # the working directory is empty; the config sits elsewhere, private
        assert list(launch.workspace.iterdir()) == []
        assert launch.workspace not in launch.mcp_config.parents
        assert stat.S_IMODE(launch.private.stat().st_mode) == 0o700
        assert stat.S_IMODE(launch.mcp_config.stat().st_mode) == 0o600
        cfg = json.loads(launch.mcp_config.read_text())
        assert list(cfg["mcpServers"]) == [esmcp.SERVER_NAME]
        server = cfg["mcpServers"][esmcp.SERVER_NAME]
        assert server["type"] == "http" and server["url"].startswith("http://127.0.0.1:")
    finally:
        launch.cleanup()
    assert not launch.workspace.exists() and not launch.private.exists()


def test_es_research_runs_claude_with_the_tools_only_and_unmasks_locally(
        monkeypatch, tmp_path, capsys):
    """The whole chain through the CLI, with a stand-in for ``claude`` that
    checks what it was handed and then behaves as an MCP client would."""
    import subprocess

    from hider import cli, research

    monkeypatch.setattr(research, "RESEARCH", tmp_path / "research")
    monkeypatch.setenv("HIDER_ELASTIC", "/somewhere/elastic.json")
    monkeypatch.setenv("KIBANA_SID", "sid=should-not-pass")
    fx = eseval.generate(docs=300)  # what the stub mode serves
    tenant = fx.tenants[0].name
    seen: dict = {}

    def fake_claude(argv, *, cwd, env, **kw):
        seen.update(argv=argv, env=env, cwd=Path(cwd), listing=list(Path(cwd).iterdir()))
        prompt = argv[argv.index("-p") + 1]
        label = re.search(r"<Org-\d+>", prompt).group(0)
        cfg = json.loads(Path(argv[argv.index("--mcp-config") + 1]).read_text())
        server = cfg["mcpServers"][esmcp.SERVER_NAME]
        c = Mcp(server["url"], server["headers"]["Authorization"].split()[1])
        c.rpc("initialize", {"protocolVersion": "2025-06-18"})
        n, err = c.tool("es_count", index="logs-app-*",
                        filters=[{"field": "labels.tenant_name", "op": "eq", "value": label}])
        assert not err
        aggs, err = c.tool("es_aggregate", index="logs-app-*", filters=[
            {"field": "labels.tenant_name", "op": "eq", "value": label}],
            aggs={"servers": {"type": "terms", "field": "agent.name", "size": 1}})
        assert not err
        seen["server_label"] = aggs["aggregations"]["servers"]["buckets"][0]["key"]
        seen["bodies"] = c.bodies
        out = {"type": "result", "is_error": False, "total_cost_usd": 0.01,
               "result": f"`{label}` has {n['hits_total']['value']} lines in logs-app-*, "
                         f"most on `{seen['server_label']}`."}
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(out), stderr="")

    monkeypatch.setattr(subprocess, "run", fake_claude)
    rc = cli.main(["es-research", "--stub", "--case", "demo", "--tier2", "none",
                   "--term", tenant, "--prompt", f"How busy is {tenant}?", "--yes"])
    out = capsys.readouterr()
    assert rc == 0, out.err
    want = _expected(fx, "logs-app-*", lambda f: f.get("labels.tenant_name") == tenant)
    from collections import Counter
    top_server = Counter(eseval.flatten(d.source).get("agent.name") for d in fx.docs
                         if d.index == "logs-app-*" and
                         eseval.flatten(d.source).get("labels.tenant_name") == tenant
                         ).most_common(1)[0][0]
    # the human's terminal gets the real values back, unmasked locally: the
    # bracketed label and the shaped server label both
    assert f"{tenant}` has {want} lines in logs-app-*, most on `{top_server}`." in out.out
    assert seen["server_label"] != top_server
    # what Claude Code was handed: a masked prompt, the allowlisted env, an empty cwd
    prompt = seen["argv"][seen["argv"].index("-p") + 1]
    assert tenant not in prompt and re.search(r"<Org-\d+>", prompt)
    assert "HIDER_ELASTIC" not in seen["env"] and "KIBANA_SID" not in seen["env"]
    assert seen["listing"] == [] and not seen["cwd"].exists()  # and cleaned up after
    assert not Path(seen["argv"][seen["argv"].index("--mcp-config") + 1]).exists()
    assert _no_truth(seen["bodies"], fx) == []
    saved = next((tmp_path / "research").iterdir())
    assert tenant not in (saved / "answer.masked.md").read_text()
    assert tenant not in (saved / "prompt.sent.txt").read_text()
    assert tenant in (saved / "answer.md").read_text()


def test_es_research_without_a_bridge_is_a_refusal(tmp_path, capsys, short_dir):
    from hider import cli

    raw = json.loads(elastic.EXAMPLE.read_text())
    raw["clusters"] = {"stub": {"kibana": "https://kibana-stub.example.net"}}
    raw["profile_dir"] = str(short_dir / "profile")
    path = short_dir / "elastic.json"
    path.write_text(json.dumps(raw))
    assert cli.main(["es-research", "--config", str(path), "--case", "c1"]) == 2
    assert "code=session_expired" in capsys.readouterr().out


def test_unmask_restores_shaped_labels_for_an_es_case_only(tmp_path, capsys):
    from hider import cli

    session = {"schema": elastic.SESSION_SCHEMA,
               "mapping": {"<Org-01>": "Contoso Group", "ctr-amer-s01": "ctr-amer-042",
                           "ctr-amer-s011": "ctr-amer-777"}, "types": {}}
    case = tmp_path / "session.json"
    case.write_text(json.dumps(session))
    answer = tmp_path / "a.md"
    answer.write_text("`<Org-01>` on ctr-amer-s01 and ctr-amer-s011, not ctr-amer-s01x or "
                      "host.ctr-amer-s01.")
    assert cli.main(["unmask", str(answer), "--mapping", str(case)]) == 0
    assert capsys.readouterr().out == ("`Contoso Group` on ctr-amer-042 and ctr-amer-777, not "
                                       "ctr-amer-s01x or host.ctr-amer-s01.")
    plain = tmp_path / "run.mapping.json"
    plain.write_text(json.dumps({"mapping": session["mapping"]}))
    assert cli.main(["unmask", str(answer), "--mapping", str(plain)]) == 0
    assert "on ctr-amer-s01 and" in capsys.readouterr().out  # a JSON run: unchanged


# -- the prompt gate -----------------------------------------------------------


def _case_mapping():
    s = elastic.EsScrubber(CFG0, tier2="none")
    labels = {"org": s.seed("Contoso Group"), "server": s.seed("ctr-amer-042", "SERVER_NAME"),
              "email": s.seed("anna.lind@contoso.com", "UPN_EMAIL"),
              "ip": s.seed("10.44.2.17", "IPV4"),
              "tenant": s.seed("0f9e8d7c-6b5a-4433-9221-0a1b2c3d4e5f", "TENANT_ID")}
    s._remember("Info", "<Org-09>", "ORG_NAME")  # an older case's log word
    return dict(s.mapping), labels


def _findings(text, mapping, known=True):
    return esmcp.prompt_findings(text, mapping, seedable=esmcp.seedable_types(CFG0),
                                 shapes=esmcp.config_shapes(CFG0), known=known)


def test_labels_field_names_and_date_math_pass_the_prompt_gate():
    mapping, lab = _case_mapping()
    assert lab["email"].endswith(".example") and lab["ip"].startswith("203.0.113.")
    prompt = (f"Why did {lab['org']} fail on {lab['server']} for {lab['email']} from {lab['ip']} "
              f"in tenant {lab['tenant']}? Count by agent.name and host.name in logs-app-* over "
              "now-7d, log.level error, HTTP 429, since 2026-08-20T10:00:00Z, region amer. "
              "Also <Person-77>, user-05@tenant-03.example and Info lines.")
    assert _findings(prompt, mapping) == []


@pytest.mark.parametrize("value,etype,hint", [
    ("bob.smith@fabrikam.com", "UPN_EMAIL", "--term UPN_EMAIL=<the value>"),
    ("7c1d2e3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f", "GUID", "--term GUID=<the value>"),
    ("tenant 7c1d2e3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f", "TENANT_ID", "--term TENANT_ID=<the value>"),
    ("10.1.2.3", "IPV4", "--term IPV4=<the value>"),
    ("ctr-emea-117", "SERVER_NAME", "--term SERVER_NAME=<the value>"),
    ("web01.fabrikam.com", "CUSTOMER_DOMAIN", "has no CUSTOMER_DOMAIN field"),
    ("password=Sup3rS3cret!", "CONNECTION_STRING", "never seeded"),
])
def test_an_unseeded_identifier_in_the_prompt_is_refused_by_type(value, etype, hint):
    mapping, lab = _case_mapping()
    out = _findings(f"what happened to {value} and {lab['org']}?", mapping)
    mine = [f for f in out if f"a {etype} value" in f]
    assert mine and hint in mine[0], out
    # nothing else in it is a finding (".com" is not a word to refuse). A
    # credential may be claimed by two secret rules at once - password= is
    # both a connection string and a key-name assignment - and both say
    # "take it out", so the refusal is the same refusal twice.
    others = [f for f in out if f not in mine]
    assert all("credentials are destroyed" in f for f in others), out
    bare = value.split()[-1]
    assert all(bare not in f and "fabrikam" not in f.lower() for f in out)


def test_the_interactive_gate_refuses_a_held_value_by_naming_its_label():
    mapping, lab = _case_mapping()
    out = _findings("how busy is Contoso Group on ctr-amer-042?", mapping)
    assert f"type {lab['org']} instead" in out[0] and f"type {lab['server']} instead" in out[1]
    assert all("Contoso" not in f and "042" not in f for f in out)
    # "Contoso" is a value of its own (the organisation's core name)
    assert "type <Org-" in _findings("anything about Contoso?", mapping)[0]
    # a run that only appears inside a value (the head of the tenant GUID)
    words = _findings("anything in 0f9e8d7c?", mapping)
    assert words and "from inside a customer value" in words[0] and "0f9e8d7c" not in words[0]
    # headless masks first, so there the held value is not a finding
    assert _findings("how busy is Contoso Group?", mapping, known=False) == []


def _research_case(monkeypatch, tmp_path):
    import subprocess

    from hider import research

    monkeypatch.setattr(research, "RESEARCH", tmp_path / "research")
    launched: list = []

    def fake_claude(argv, **kw):
        launched.append(argv)
        out = {"type": "result", "is_error": False, "result": "ok", "num_turns": 1}
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(out), stderr="")

    monkeypatch.setattr(subprocess, "run", fake_claude)
    return launched


@pytest.mark.parametrize("value", ["bob.smith@fabrikam.com", "7c1d2e3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f"])
def test_es_research_refuses_an_unseeded_identifier_even_with_yes(monkeypatch, tmp_path, capsys,
                                                                    value):
    from hider import cli

    launched = _research_case(monkeypatch, tmp_path)
    rc = cli.main(["es-research", "--stub", "--case", "demo", "--tier2", "none",
                   "--term", "Contoso Group", "--yes",
                   "--prompt", f"Contoso Group and {value}: what failed?"])
    out = capsys.readouterr()
    assert rc == 2 and launched == []
    assert "REFUSED  code=prompt_identifier" in out.out and "seed it with --term" in out.out
    assert value not in out.out + out.err


def test_es_research_lets_labels_through_and_installs_the_hook(monkeypatch, tmp_path, capsys):
    from hider import cli

    launched = _research_case(monkeypatch, tmp_path)
    rc = cli.main(["es-research", "--stub", "--case", "demo", "--tier2", "none", "--yes",
                   "--term", "Contoso Group", "--term", "SERVER_NAME=ctr-amer-042",
                   "--prompt", "Is Contoso Group busy on ctr-amer-042 or on ctr-amer-s01 and "
                               "<Org-01> in logs-app-* over now-7d?"])
    assert rc == 0, capsys.readouterr()
    argv = launched[0]
    prompt = argv[argv.index("-p") + 1]
    assert "Contoso" not in prompt and "042" not in prompt and "ctr-amer-s01" in prompt
    assert "--settings" in argv


def test_interactive_es_research_checks_every_typed_prompt(monkeypatch, tmp_path, capsys):
    """No prompt on the command line: the hook is what stands between what
    the human types and Claude. Checked while the launch exists, as Claude
    Code would run it."""
    import subprocess

    from hider import cli

    seen = {}

    def fake_claude(argv, **kw):
        settings = json.loads(Path(argv[argv.index("--settings") + 1]).read_text())
        cmd = settings["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"]
        assert cmd.endswith("|| exit 2")
        check = re.search(r"es-prompt-check (\S+)", cmd).group(1)
        seen["check"] = check
        for prompt, code in [("how busy is <Org-01>?", 0), ("how busy is Contoso Group?", 2),
                             ("what about bob.smith@fabrikam.com?", 2)]:
            monkeypatch.setattr("sys.stdin", __import__("io").StringIO(
                json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": prompt})))
            seen[prompt] = cli.main(["es-prompt-check", check])
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(subprocess, "run", fake_claude)
    assert cli.main(["es-research", "--stub", "--case", "demo", "--tier2", "none",
                     "--term", "Contoso Group"]) == 0
    err = capsys.readouterr().err
    assert seen["how busy is <Org-01>?"] == 0
    assert seen["how busy is Contoso Group?"] == 2 and seen["what about bob.smith@fabrikam.com?"] == 2
    assert "type <Org-01> instead" in err and "a UPN_EMAIL value" in err
    assert "fabrikam" not in err and "Contoso Group" not in err.split("seeded")[0]
    assert not Path(seen["check"]).exists()  # the launch was cleaned up


def test_the_hook_blocks_when_it_cannot_check(monkeypatch, tmp_path, capsys):
    import io

    from hider import cli

    for stdin, check in [("not json", str(tmp_path / "missing.json")),
                         (json.dumps({"prompt": "hi"}), str(tmp_path / "missing.json"))]:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
        assert cli.main(["es-prompt-check", check]) == 2
    assert "the prompt check failed" in capsys.readouterr().err


def test_schema_and_instructions_warn_about_keep_field_spellings(bridge):
    """log.level on a real cluster holds err and Error and INFO side by side;
    an exact filter on one spelling looks like absence. Claude is told, in
    both places it reads, to aggregate a keep field's actual values first
    and then filter with `in` across the spellings it saw."""
    opened = bridge.open()
    schema, err = Mcp(opened["url"], opened["token"]).tool("es_schema")
    assert not err
    keep = schema["kinds"]["keep"]
    assert "as logged" in keep and "in" in keep and "spelling" in keep
    for text in (esmcp.INSTRUCTIONS, keep):
        assert "aggregate" in text.lower() and "spelling" in text.lower()
    assert "exact filter" in esmcp.INSTRUCTIONS and "op in" in esmcp.INSTRUCTIONS
    # and it says what a zero means, so "no errors" is not reported as fact
    assert "Zero hits" in esmcp.INSTRUCTIONS
