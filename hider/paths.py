"""The one vocabulary for file paths in free text: what is structure, not customer.

``recognizers.CustomerPathRecognizer`` labels every customer folder and file
name in a path and leaves the rest readable. "The rest" is decided here and
nowhere else:

* :data:`STRUCTURAL` - folder names that are the same for every customer
  (``Shared Documents``, ``AppData``, ``Exports``). A segment matching one,
  case-insensitively and with ``%20`` read as a space, stays readable.
* :data:`WINDOWS_SYSTEM_ROOTS` and :data:`POSIX_SYSTEM_ROOTS` - a path under
  one is an operating-system or application path: its folders stay
  readable, and only a document file name under it is labelled.
* :data:`CODE_EXT` and :data:`BINARY_EXT` - a path ending in a source file
  or a program binary stays readable whole, so stack traces and install
  paths keep their triage value.
* :data:`API_ROOTS` - a leading-slash path starting with one is an API
  route, not a file.

Site-specific structure (a department-neutral folder every customer of one
product has) goes in ``hider.local.json`` as ``"path_structure": [...]``,
never in the repo. The list only ever makes more readable, so a site entry
must be a name that identifies no customer.
"""

from __future__ import annotations

import re

from . import localcfg

#: Folder names that are structure, not customer content. Compared with
#: :func:`norm`, so case, ``%20`` and typographic apostrophes do not matter.
STRUCTURAL: frozenset[str] = frozenset({
    # document libraries and collaboration structure
    "shared documents", "documents", "shared", "sites", "site assets", "siteassets",
    "site pages", "sitepages", "style library", "lists", "forms", "pages",
    "attachments", "general", "teams", "personal", "portals",
    # profile and shell folders
    "desktop", "downloads", "pictures", "music", "videos", "public", "favorites",
    "appdata", "local", "locallow", "roaming", "temp", "tmp", "cache",
    # system and application structure under a customer root
    "program files", "program files (x86)", "programdata", "windows", "system32",
    "syswow64", "microsoft", "bin", "lib", "etc", "config", "logs", "log",
    # generic work folders: the same word at every customer
    "backup", "backups", "archive", "archives", "export", "exports", "import",
    "imports", "reports", "data", "shares", "share", "common", "users", "apps",
    "old", "new folder", "staging", "incoming", "outgoing", "restore", "restores",
    # mailbox folders
    "inbox", "outbox", "sent items", "deleted items", "drafts", "archive mailbox",
    # administrative shares
    "c$", "d$", "e$", "admin$", "ipc$", "sysvol", "netlogon",
    *(s.casefold() for s in localcfg.settings().get("path_structure", [])),
})

#: A drive path whose first folder is one of these is a system path.
WINDOWS_SYSTEM_ROOTS: frozenset[str] = frozenset({
    "windows", "program files", "program files (x86)", "programdata",
    "$recycle.bin", "system volume information", "recovery", "perflogs",
    "inetpub", "windows.old", "boot",
})

#: A leading-slash path whose first folder is one of these is a system path.
POSIX_SYSTEM_ROOTS: frozenset[str] = frozenset({
    "usr", "var", "etc", "opt", "proc", "sys", "lib", "lib32", "lib64", "bin",
    "sbin", "dev", "run", "boot", "tmp", "srv", "snap", "nix", "private",
    "library", "system", "applications", "src", "app",
})

#: Roots that are a person's own folder: the next segment is the account.
PROFILE_ROOTS: frozenset[str] = frozenset({"home", "users"})

#: Server-relative collaboration roots: a leading-slash path under one is a
#: document path even when nothing else in it says so.
LIBRARY_ROOTS: frozenset[str] = frozenset({"sites", "teams", "personal", "portals"})

#: Library names that anchor a path with no root ("Shared Documents/x.docx").
RELATIVE_ANCHORS: tuple[str, ...] = ("Shared Documents", "Shared%20Documents",
                                     "Site Assets", "SiteAssets")

#: First segments of API routes, never files.
API_ROOTS: frozenset[str] = frozenset({
    "api", "_api", "_layouts", "_vti_bin", "v1.0", "beta", "odata", "rest",
    "oauth2", "graph", ".well-known", "health", "healthz", "metrics", "status",
    "swagger", "signin-oidc", "auth", "token", "login", "logout",
})
_API_VERSION = re.compile(r"^v\d+(?:\.\d+)?$")

#: Source files: a path to one is a stack-trace or build path.
CODE_EXT: frozenset[str] = frozenset({
    "cs", "vb", "fs", "py", "java", "kt", "scala", "go", "rs", "c", "cc", "cpp",
    "cxx", "h", "hpp", "js", "jsx", "ts", "tsx", "mjs", "rb", "php", "swift",
    "m", "mm", "pl", "lua", "ps1", "psm1", "psd1", "sh", "bash", "groovy",
    "xaml", "razor", "cshtml",
})

#: Program binaries: a path to one is an install path.
BINARY_EXT: frozenset[str] = frozenset({
    "dll", "exe", "so", "dylib", "pdb", "sys", "msi", "jar", "class", "pyc",
    "whl", "node", "a", "lib", "o", "obj",
})

#: Documents: the file name is labelled even under a system root.
DOCUMENT_EXT: frozenset[str] = frozenset({
    "xlsx", "xlsm", "xls", "docx", "docm", "doc", "pptx", "pptm", "ppt", "pdf",
    "csv", "txt", "rtf", "odt", "ods", "odp", "msg", "eml", "pst", "ost", "one",
    "vsdx", "pages", "numbers", "key", "md", "zip", "7z", "rar", "jpg", "jpeg",
    "png", "gif", "bmp", "tif", "tiff", "heic", "mp4", "mov", "mp3", "wav",
    "vbk", "vib", "vbm", "vrb", "bak",
})

#: Version and number segments stay readable: 12.3.1, v2, 2026, 2026-08-20.
_VERSION = re.compile(r"^(?:v?\d+(?:[._]\d+)+|v?\d{1,4}|\d{4}-\d{2}(?:-\d{2})?|x64|x86|arm64|amd64)$",
                      re.IGNORECASE)


def norm(segment: str) -> str:
    """How a segment is compared with the lists: case-folded, ``%20`` as a
    space, typographic apostrophes as straight ones, spaces collapsed."""
    s = segment.replace("%20", " ").replace("’", "'").replace("‘", "'")
    return " ".join(s.split()).casefold()


def is_structural(segment: str) -> bool:
    return norm(segment) in STRUCTURAL


def is_version(segment: str) -> bool:
    return bool(_VERSION.match(segment.strip()))


def is_api_root(segment: str) -> bool:
    s = norm(segment)
    return s in API_ROOTS or bool(_API_VERSION.match(s))
