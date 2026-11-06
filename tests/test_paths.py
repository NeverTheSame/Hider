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
    gaps = {c.case_id: c for c in adversarial.CASES if c.case_id in {
        "path-rootless-relative", "path-lowercase-final-folder-in-prose",
        "path-customer-folder-under-system-root", "path-customer-folder-in-profile-tail",
        "path-repository-name-in-source-path", "bare-file-name-in-prose"}}
    assert len(gaps) == 6 and all(not c.expect_tier1 and c.owner for c in gaps.values())


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
