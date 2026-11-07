"""Customer file paths in free text: tier 1 labels the customer parts and
leaves structure readable. Invented names only.

Intent tests, beside the adversarial cases (path-*) and the lookalike unit
(adversarial.PATH_LOOKALIKES) that the eval scores.
"""

from __future__ import annotations

import importlib
import json

import pytest

from hider import adversarial, jsonscrub, localcfg, paths, pipeline, pseudonym


def _tier1(key: bytes = b"k") -> pipeline.Pipeline:
    return pipeline.Pipeline([pipeline.RegexTier()], vault=pseudonym.EntityVault(key=key))


@pytest.mark.parametrize("line,want", [
    ("Uploaded /Sites/Finance/Shared Documents/Harbor Ridge Project (HRP)/Board Notes - Drafts/Budget.docx",
     "Uploaded /Sites/<Folder-01>/Shared Documents/<Folder-02>/<Folder-03>/<File-01>.docx"),
    (r"Export failed for C:\Exports\Airplane Trust\Payroll Review.xlsx: access denied",
     r"Export failed for C:\Exports\<Folder-01>\<File-01>.xlsx: access denied"),
    ("wrote D:/Shares/Northgate Fund/Quarterly Review (Final).pptx in 3 s",
     "wrote D:/Shares/<Folder-01>/<File-01>.pptx in 3 s"),
    ("Restored C:\\Exports\\Harbor Partners\u2019 Files\\Members\u2019 List 2026.xlsx",
     r"Restored C:\Exports\<Folder-01>\<File-01>.xlsx"),
    (r"slow read on \\FS01\FINANCE\HRP BOARD\BUDGET 2026.XLSX",
     r"slow read on \\node-01.tenant.example\<Folder-01>\<Folder-02>\<File-01>.XLSX"),
    (r"source E:\Clients/Bramble Hill\Ledger.csv", r"source E:\<Folder-01>/<Folder-02>\<File-01>.csv"),
    (r'Copy target "D:\Shares\Airplane Trust\Year End Close" is read-only',
     r'Copy target "D:\Shares\<Folder-01>\<Folder-02>" is read-only'),
    (r"Restore to C:\Exports\Harbor Ridge Project completed in 4 s",
     r"Restore to C:\Exports\<Folder-01> completed in 4 s"),
    ("queued /sites/Finance/Shared%20Documents/Board%20Notes/Budget.docx",
     "queued /sites/<Folder-01>/Shared%20Documents/<Folder-02>/<File-01>.docx"),
    ("staged /home/lena.okafor/Bramble Hill/notes.txt", "staged /home/user-01/<Folder-01>/<File-01>.txt"),
    ('body {"path":"D:\\\\Shares\\\\Northgate Fund\\\\Ledger Q3.xlsx"}',
     'body {"path":"D:\\\\Shares\\\\<Folder-01>\\\\<File-01>.xlsx"}'),
    ("Restored Shared Documents/Harbor Ridge/Budget.docx", "Restored Shared Documents/<Folder-01>/<File-01>.docx"),
    (r"C:\Windows\Temp\Payroll Review.xlsx was left behind", r"C:\Windows\Temp\<File-01>.xlsx was left behind"),
    (r"export to C:\Exports\Airplane Trust, 4 files", r"export to C:\Exports\<Folder-01>, 4 files"),
])
def test_customer_parts_become_labels_and_structure_stays(line, want):
    assert _tier1().redact(line).text == want


@pytest.mark.parametrize("line", adversarial.PATH_LOOKALIKES)
def test_system_source_api_and_version_paths_stay_readable(line):
    assert _tier1().redact(line).text == line


@pytest.mark.parametrize("line", [
    "GET /Sites/Finance/Lists/Tasks returned 200",           # an HTTP route, whatever its case
    "routed to /api/Jobs/Start in 4 ms",                      # an API root
    "flag /Finance is ignored",                               # one segment: a switch
    r"at Run() in D:\Repos\Harbor Ridge\src\Program.cs:line 12",   # source file
    r"loaded D:\Clients\Harbor Ridge\bin\Ledger.Core.dll",        # program binary
    "kept /var/opt/Harbor Ridge/state.json",                  # system root, no document
    "saved https://files.example.org/Exports/Payroll Review.xlsx",  # a URL: the host rules own it
])
def test_each_fence_keeps_its_path_readable(line):
    spans = [s for s in _tier1().redact(line).spans
             if s.entity_type in {"PATH_SEGMENT", "FILE_NAME", "PATH_ACCOUNT"}]
    assert spans == []


def test_the_same_path_gets_the_same_labels_on_every_line_and_run():
    lines = [r"read C:\Exports\Airplane Trust\Payroll Review.xlsx",
             r"retry C:/Exports/airplane trust/PAYROLL REVIEW.xlsx",   # case and slashes differ
             r"done C:\Exports\Airplane Trust\Board.docx"]
    a, b = _tier1(b"same"), _tier1(b"same")
    outs = [a.redact(x).text for x in lines]
    assert outs == [r"read C:\Exports\<Folder-01>\<File-01>.xlsx",
                    "retry C:/Exports/<Folder-01>/<File-01>.xlsx",
                    r"done C:\Exports\<Folder-01>\<File-02>.docx"]
    assert [b.redact(x).text for x in lines] == outs  # same key, same labels


def test_path_values_are_pseudonymised_never_left_or_destroyed():
    vault = pseudonym.EntityVault(key=b"k")
    line = r"Export failed for \\FS01\FINANCE\HRP BOARD\BUDGET 2026.XLSX"
    out = pipeline.Pipeline([pipeline.RegexTier()], vault=vault).redact(line).text
    held = {e["value"]: e["type"] for e in vault.entries.values() if not e["type"].startswith("_")}
    assert held == {"FS01": "HOSTNAME_FQDN", "FINANCE": "PATH_SEGMENT",
                    "HRP BOARD": "PATH_SEGMENT", "BUDGET 2026": "FILE_NAME"}
    assert not any(v in out for v in held)
    assert "<REDACTED" not in out


def test_a_logon_shape_inside_a_path_is_folders_and_outside_still_a_logon():
    out = _tier1().redact(r"CONTOSO\anna.novak opened C:\Exports\HRP BOARD\BUDGET.XLSX").text
    assert out == r"DOMAIN01\user-01 opened C:\Exports\<Folder-01>\<File-01>.XLSX"


def test_known_paths_are_swept_through_a_json_export():
    r = jsonscrub.scrub({"note": r"Export failed for C:\Exports\Airplane Trust\Payroll Review.xlsx",
                         "later": "Airplane Trust retried"}, tier2="none")
    assert r.output == {"note": r"Export failed for C:\Exports\<Folder-01>\<File-01>.xlsx",
                        "later": "<Folder-01> retried"}


def test_declared_misses_stay_declared():
    """Each is an adversarial case with expect_tier1=False and an owner; this
    pins what tier 1 alone does with them, so a change is noticed."""
    t = _tier1()
    assert t.redact(r"Copied to C:\Exports\larch valley trust overnight").text == \
        r"Copied to C:\Exports\<Folder-01> valley trust overnight"
    for line in ("Restored item Cobalt Meadow/Grant Ledger.docx to the site",
                 "rotated /var/log/Owl Creek Holdings/agent.log",
                 "uploaded Fernhill Payroll.xlsx to the share"):
        assert t.redact(line).text == line
    long_name = ("Kestrel Row notes from the second planning meeting about the "
                 "new west wing extension and the parking area")
    out = _tier1().redact(rf"Copied C:\Shares\Bramble Hill\{long_name}.docx to backup").text
    assert out == (r"Copied C:\Shares\<Folder-01>\<Folder-02> notes from the second planning "
                   r"meeting about the new west wing extension and the parking area.docx to backup")
    assert _tier1().redact(r"Copied C:\Shares\Bramble Hill\Kestrel Row payroll final to backup").text \
        == r"Copied C:\Shares\<Folder-01>\<Folder-02> payroll final to backup"
    src = r"Restore to C:\Exports\Cormorant Quay Done See Program.cs"
    assert t.redact(src).text == src
    gaps = {c.case_id: c for c in adversarial.CASES if c.case_id in {
        "path-rootless-relative", "path-lowercase-final-folder-in-prose",
        "path-customer-folder-under-system-root", "path-customer-folder-in-profile-tail",
        "path-repository-name-in-source-path", "bare-file-name-in-prose",
        "path-file-name-over-sixteen-words", "path-file-extensionless-in-prose",
        "path-folder-then-source-file-after-title-case-words"}}
    assert len(gaps) == 9 and all(not c.expect_tier1 and c.owner for c in gaps.values())


# -- the last segment is a file name, labelled whole or not at all ----------
#
# A blind test on real bundles found "<Folder-03> payroll.xlsb": a folder
# label over the first words of a file name and the rest readable. Each shape
# below fell back for a reason named in its adversarial case (path-file-*).

_LIB = "/Sites/Finance/Shared Documents/Harbor Ridge/"
_LIB_OUT = "/Sites/<Folder-01>/Shared Documents/<Folder-02>/"


@pytest.mark.parametrize("name,ext_kept", [
    ("Alpine Trust: 09-16-22 with staff IDs", ".xlsx"),           # colon
    ("Alpine Trust, LLC FINAL signed copy", ".pdf"),              # comma, all caps
    ("Alpine Trust quarterly review of the northern region board meeting final draft", ".docx"),
    ("WO-12345 Alpine Trust roof repair quote", ".pdf"),          # work-order code
    ("Alpine Trust $1,250.00 March invoice", ".pdf"),             # amount and month
    ("Alpine  Trust payroll", ".xlsx"),                           # double space
    ("Alpine\u00a0Trust payroll", ".xlsx"),                       # non-breaking space
    ("Alpine\u202fTrust payroll", ".xlsx"),                       # narrow no-break space
    ("Alpine Trust payroll", ".xlsb"),                            # Office binary workbook
])
def test_a_file_name_is_one_label_with_its_known_extension_readable(name, ext_kept):
    for line, want in [
        (f"Uploaded {_LIB}{name}{ext_kept} in 2 s", f"Uploaded {_LIB_OUT}<File-01>{ext_kept} in 2 s"),
        (f'Upload failed for "{_LIB}{name}{ext_kept}"', f'Upload failed for "{_LIB_OUT}<File-01>{ext_kept}"'),
        (f"Copied C:\\Shares\\Finance\\{name}{ext_kept}, retrying",
         f"Copied C:\\Shares\\<Folder-01>\\<File-01>{ext_kept}, retrying"),
    ]:
        r = _tier1().redact(line)
        assert r.text == want, line
        files = [s for s in r.spans if s.entity_type == "FILE_NAME"]
        assert len(files) == 1 and line[files[0].start:files[0].end] == name


@pytest.mark.parametrize("seg", [
    "Alpine Trust payroll.xlsl",
    "Alpine Trust: 09-16-22 with staff IDs.xlsl",
    "ALPINE TRUST PAYROLL.XLSL",
    "payroll.qbw2",
])
def test_an_unknown_extension_is_hidden_with_the_name(seg):
    """Nothing says an extension on no list is not part of the name, so the
    whole segment is one label; the engineer loses the file type, not more."""
    for line, want in [
        (f"{_LIB}{seg} was locked by another user", f"{_LIB_OUT}<File-01> was locked by another user"),
        (f'failed for "{_LIB}{seg}"', f'failed for "{_LIB_OUT}<File-01>"'),
    ]:
        r = _tier1().redact(line)
        assert r.text == want, line
        assert [line[s.start:s.end] for s in r.spans if s.entity_type == "FILE_NAME"] == [seg]


def test_no_folder_label_ever_lands_inside_the_last_segment():
    """The property the blind test broke, over every shape at once: the last
    segment carries exactly one label, and it is a file label."""
    stems = ["Alpine Trust: 09-16-22 with staff IDs", "Alpine Trust payroll",
             "Alpine  Trust payroll", "Alpine\u00a0Trust payroll", "WO-12345 Alpine Trust renewal",
             "Alpine Trust $1,250 March", "Alpine Trust, LLC FINAL copy",
             "Alpine Trust one two three four five six seven eight nine ten"]
    for stem in stems:
        for ext in (".xlsx", ".xlsb", ".xlsl", ".pdf"):
            for tail in ("", " was locked by another user", ": access denied", " (412 KB)"):
                line = f"{_LIB}{stem}{ext}{tail}"
                spans = _tier1().redact(line).spans
                last_start = len(_LIB)
                inside = [s for s in spans if s.end > last_start]
                assert [s.entity_type for s in inside] == ["FILE_NAME"], line
                assert inside[0].start == last_start
                assert line[inside[0].end:].startswith(ext if ext != ".xlsl" else tail), line


def test_a_file_keeps_one_label_across_hits_spellings_and_pages():
    """One file, followed through a bundle: the same label however a layer
    spelled the spaces (NBSP, doubled, %20) or the case."""
    lines = [f"read {_LIB}Alpine Trust payroll.xlsb",
             f"retry {_LIB}Alpine\u00a0Trust payroll.xlsb",
             f"retry {_LIB}Alpine  Trust  payroll.xlsb",
             "queued /Sites/Finance/Shared%20Documents/Harbor%20Ridge/Alpine%20Trust%20payroll.xlsb",
             f"done {_LIB}ALPINE TRUST PAYROLL.xlsb",
             f"other {_LIB}Alpine Trust payroll March.xlsb"]
    t = _tier1(b"same")
    outs = [t.redact(x).text for x in lines]
    assert outs[:3] == [f"read {_LIB_OUT}<File-01>.xlsb", f"retry {_LIB_OUT}<File-01>.xlsb",
                        f"retry {_LIB_OUT}<File-01>.xlsb"]
    assert outs[3] == "queued /Sites/<Folder-01>/Shared%20Documents/<Folder-02>/<File-01>.xlsb"
    assert outs[4] == f"done {_LIB_OUT}<File-01>.xlsb"
    assert outs[5] == f"other {_LIB_OUT}<File-02>.xlsb"  # a different file, a different label
    again = _tier1(b"same")
    assert [again.redact(x).text for x in lines] == outs  # same key, same labels


def test_a_file_keeps_one_label_across_elasticsearch_hits_and_pages():
    from hider import elastic
    s = elastic.EsScrubber(elastic.load(elastic.EXAMPLE), tier2="none")
    plan = elastic.Plan("logs-app-*")

    def page(*messages):
        hits = [{"_index": "logs-app-2026.08.20", "_id": f"h{i}", "_score": None,
                 "_source": {"@timestamp": "2026-08-20T10:00:00.000Z", "message": m}}
                for i, m in enumerate(messages)]
        raw = {"took": 1, "timed_out": False, "hits": {"total": {"value": len(hits), "relation": "eq"},
                                                        "max_score": None, "hits": hits}}
        out = s.scrub_response({"id": "s", "isPartial": False, "isRunning": False,
                                "rawResponse": raw}, plan).output
        return [h["_source"]["message"] for h in out["hits"]["hits"]]

    first = page(f"Upload failed for {_LIB}Alpine Trust: 09-16-22 with staff IDs.xlsl",
                 f"Retry 2 for {_LIB}Alpine Trust: 09-16-22 with staff IDs.xlsl")
    second = page(f"Upload failed for {_LIB}Alpine Trust:\u00a009-16-22 with staff IDs.xlsl")
    labels = {m.rsplit("/", 1)[1] for m in first + second}
    assert len(labels) == 1 and "Alpine" not in "".join(first + second)


def test_a_file_name_is_vaulted_whole_never_in_pieces():
    vault = pseudonym.EntityVault(key=b"k")
    line = f"Upload failed for {_LIB}Alpine Trust: 09-16-22 with staff IDs.xlsl"
    out = pipeline.Pipeline([pipeline.RegexTier()], vault=vault).redact(line).text
    held = {e["value"]: e["type"] for e in vault.entries.values() if not e["type"].startswith("_")}
    assert held == {"Finance": "PATH_SEGMENT", "Harbor Ridge": "PATH_SEGMENT",
                    "Alpine Trust: 09-16-22 with staff IDs.xlsl": "FILE_NAME"}
    assert "Alpine" not in out and "staff" not in out


@pytest.mark.parametrize("line", [
    # the name reader must not turn any of these into a customer file name
    "route /jobs/run/status answered 200, details in agent.log",
    r"started C:\Program Files\Backup Agent\Agent Host Service.exe as svc",
    r"logging to C:\ProgramData\BackupAgent\Logs\Agent Service.log",
    "key ~/.ssh/id_rsa.pub accepted",
    "installed under /opt/agent/12.3.1/bin: version 12.3.1.1139 ready",
    "crawling /sites/portals/Shared Documents/Forms finished in 3 s",
    r"at Run() in D:\a\1\s\src\Proxy\SessionWorker.cs:line 214, retrying",
    "GET /v1.0/sites/root/drives/items returned 200, see trace.json",
    "flag /Finance is ignored; see e.g. the docs",
])
def test_the_file_name_reader_leaves_application_paths_readable(line):
    assert _tier1().redact(line).text == line


def test_a_version_or_a_host_after_a_folder_is_not_its_extension():
    assert _tier1().redact("copied /Sites/Finance/Shared Documents/Harbor Ridge to node.v2 at 10:22").text \
        == "copied /Sites/<Folder-01>/Shared Documents/<Folder-02> to node.v2 at 10:22"
    out = _tier1().redact("synced /Sites/Finance/Harbor Ridge to fs01.contoso.local at 10:22").text
    assert out == "synced /Sites/<Folder-01>/<Folder-02> to node-01.tenant.example at 10:22"


def test_prose_before_a_later_file_on_the_line_is_hidden_with_the_name():
    """Declared over-destruction, the price of reading on to an extension:
    an unquoted folder path followed by prose that names a file within
    sixteen words reads as one long file name. It errs toward hiding, which
    is also what closed two older leaks (a spaced name ending in .log stayed
    readable whole, as an application artifact)."""
    t = _tier1()
    assert t.redact(r"Restore to C:\Exports\Harbor Ridge Project completed in 4 s, then wrote "
                    r"summary.xlsx for the audit").text == r"Restore to C:\Exports\<File-01>.xlsx for the audit"
    assert t.redact(r"read C:\Exports\Harbor Ridge sync.log").text == r"read C:\Exports\<File-02>.log"


def test_site_structure_extends_the_list_through_hider_local(tmp_path, monkeypatch):
    local = tmp_path / "hider.local.json"
    local.write_text(json.dumps({"path_structure": ["Mandantenablage"]}))
    monkeypatch.setenv(localcfg.ENV, str(local))
    localcfg.settings.cache_clear()
    try:
        importlib.reload(paths)
        assert paths.is_structural("MANDANTENABLAGE")
        assert _tier1().redact(r"C:\Mandantenablage\Northgate Fund\Q3.xlsx").text == \
            r"C:\Mandantenablage\<Folder-01>\<File-01>.xlsx"
        local.write_text(json.dumps({"path_structure": ["ok", 3]}))
        localcfg.settings.cache_clear()
        with pytest.raises(RuntimeError, match="path_structure must list non-empty strings"):
            localcfg.settings()
    finally:
        monkeypatch.delenv(localcfg.ENV)
        localcfg.settings.cache_clear()
        importlib.reload(paths)
    assert not paths.is_structural("Mandantenablage")


# -- tier 2 and structural segments (pipeline.in_structural_path_segment) ----


def _full(key: bytes = b"k") -> pipeline.Pipeline:
    from hider import evaluate
    return pipeline.Pipeline([pipeline.RegexTier(), evaluate.build_tier2("classifier")],
                             vault=pseudonym.EntityVault(key=key))


def test_structural_segments_inside_a_path_survive_tier_2():
    line = ("Uploaded /Sites/Finance/Shared Documents/Harbor Ridge Project (HRP)"
            "/Board Notes - Drafts/Budget.docx (412 KB)")
    assert _full().redact(line).text == ("Uploaded /Sites/<Folder-01>/Shared Documents/"
                                         "<Folder-02>/<Folder-03>/<File-01>.docx (412 KB)")
    svc = r"started C:\Program Files\BackupAgent\Agent.Service.exe"
    assert _full().redact(svc).text == svc  # the "Files" of Program Files stays


def test_a_real_name_elsewhere_in_the_same_path_is_still_labelled():
    # the folders are a declared tier 1 miss under a system root; tier 2 owns
    # the organisation and must keep catching it beside structural segments
    out = _full().redact("rotated /var/log/Owl Creek Holdings/agent.log").text
    assert "Creek Holdings" not in out and "/var/log/" in out and "agent.log" in out


def test_a_structural_word_outside_a_path_is_not_the_rules_business():
    """The rule is bounded by separators: tier 2's reading of prose is
    unchanged, even when the words match the structural list. Pinned so a
    widening of the rule is a deliberate choice, not drift."""
    out = _full().redact("[Sync] library Shared Documents has 41 items").text
    assert "Shared Documents" not in out  # tier 2 still labels it in prose


def test_the_rule_never_touches_a_tier_1_span():
    # the same words under an identifier rule: tier 1 claims them, the rule
    # must not resurrect them ("Shared Documents" as a *customer* folder name
    # cannot happen by definition of the structural list, but a tier 1 span
    # that merely overlaps a separator-bounded region must stay)
    line = r"Export failed for C:\Exports\Airplane Trust\Payroll Review.xlsx"
    out = _full().redact(line).text
    assert out == r"Export failed for C:\Exports\<Folder-01>\<File-01>.xlsx"


# -- a folder path, prose, then a source file or a binary ---------------------


@pytest.mark.parametrize("line,want", [
    (r"Restore to C:\Exports\Cormorant Quay completed, see Program.cs",
     r"Restore to C:\Exports\<Folder-01> completed, see Program.cs"),
    (r"Restore to C:\Exports\Cormorant Quay completed see Program.cs",
     r"Restore to C:\Exports\<Folder-01> completed see Program.cs"),
    (r"Restore to C:\Exports\Cormorant Quay, see Program.cs",
     r"Restore to C:\Exports\<Folder-01>, see Program.cs"),
    (r"Copied D:\Shares\Gannet Moor Trust and then loaded Agent.Core.dll",
     r"Copied D:\Shares\<Folder-01> and then loaded Agent.Core.dll"),
])
def test_prose_before_a_source_file_ends_the_path_at_the_folder(line, want):
    assert _tier1().redact(line).text == want


@pytest.mark.parametrize("line", [
    r"started D:\Apps\Backup Agent\Agent Host Service.exe as svc",     # spaced program name
    r"started C:\Program Files\Backup Agent\Agent host service.exe",   # under a system root
    r"started D:\Apps\Backup Agent\agent host.exe as svc",             # nothing between
    r"at Run() in D:\Repos\Harbor Ridge\src\Program.cs:line 12",       # a stack trace
])
def test_program_and_source_paths_with_spaces_stay_readable(line):
    assert _tier1().redact(line).text == line


def test_a_spaced_program_name_with_lower_case_words_outside_a_system_root_is_hidden():
    """Declared over-redaction, the cost of the rule above: lower-case words
    between the first word and a binary's extension read as prose, so the
    path is a customer folder path. Under a system root it stays readable."""
    assert _tier1().redact(r"started D:\Apps\Backup Agent\Agent host service.exe").text == \
        r"started D:\Apps\<Folder-01>\<Folder-02> host service.exe"
