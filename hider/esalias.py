"""Aliases at the tool boundary: the names Claude sees and types in place
of the site's real cluster keys, index patterns and field paths.

The site map's ``aliases`` section (:class:`hider.elastic.Aliases`) turns
this on. Everything behind the boundary - the grammar, the bridge, the
decision log, es-smoke, es-review, es-preflight - keeps the real names; a
person reads those. Only what goes to a research session is translated,
in two directions:

* **in**: a tool call's ``cluster``, ``index`` and every ``field`` are
  aliases. A name that is neither an alias nor one the site shows as
  written becomes :data:`hider.elastic.ALIAS_UNKNOWN`, so a real name
  typed as a guess is refused with the code and the words an invented one
  gets, and nothing is sent.
* **out**: the site map, the tool schemas, a reply's ``cluster``, each
  hit's ``_index`` and the keys of its ``_source``, the ``empty`` block and
  a refusal's message carry aliases.

Structure is renamed, data never is: a message text, a group text, a
bucket key and a keep value leave exactly as the scrubber made them. A
field called ``message`` must not rewrite the word in a log line, and a
keep value Claude reads is one it may type back.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

from . import elastic


class Unmapped(Exception):
    """A reply holds a name the alias map cannot place. The caller refuses
    the reply whole (``bridge_error``): shown as written it would be a real
    name the site did not choose to show."""


def state(config: elastic.ElasticConfig) -> dict:
    """Whether a site map aliases its names, as counts only: per kind how
    many names go out under an alias and how many as written. What es-login
    prints, asked of the bridge (its site map is the one in force)."""
    a = config.aliases
    if a is None:
        return {"on": False}
    return {"on": True, **{kind: [sum(1 for _, v in pairs if v is not None),
                                  sum(1 for _, v in pairs if v is None)]
                           for kind, pairs in (("clusters", a.clusters), ("indices", a.indices),
                                               ("fields", a.fields))}}


class Translator:
    def __init__(self, config: elastic.ElasticConfig):
        a = config.aliases
        if a is None:
            raise ValueError("this site map has no aliases")
        self.config = config
        self._clusters = dict(a.clusters)
        self._indices = dict(a.indices)
        self._fields = dict(a.fields)
        self._cluster_in = {v: k for k, v in a.clusters if v is not None}
        self._index_in = {v: k for k, v in a.indices if v is not None}
        self._field_in = {v: k for k, v in a.fields if v is not None}
        # a refusal names fields, an index or a cluster by their real name
        # (the grammar works in real names); longest first, whole names only
        real = {**{k: v for k, v in a.fields if v is not None},
                **{k: v for k, v in a.indices if v is not None},
                **{k: v for k, v in a.clusters if v is not None}}
        self._real = real
        self._real_rx = (re.compile(
            r"(?<![\w.@*-])(?:" + "|".join(re.escape(k) for k in sorted(real, key=len, reverse=True))
            + r")(?![\w@*-]|\.\w)") if real else None)

    @classmethod
    def of(cls, config: elastic.ElasticConfig) -> "Translator | None":
        return cls(config) if config.aliases is not None else None

    # -- names -------------------------------------------------------------

    def cluster_out(self, name: str) -> str:
        if name not in self._clusters:
            raise Unmapped("cluster")
        return self._clusters[name] or name

    def index_out(self, pattern: str) -> str:
        return self._indices[pattern] or pattern

    def field_out(self, path: str) -> str:
        """The name a concrete field path goes out under: its rule's alias,
        or the path itself where the site shows that rule as written."""
        rule = self.config.rule(path)
        if rule is None:
            raise Unmapped("field")
        return self._fields[rule.pattern] or path

    def hit_index_out(self, name: str) -> str:
        """A hit's ``_index`` is a concrete name (a backing index, a dated
        index): it goes out as the alias of the pattern it belongs to."""
        bare = elastic._UNWRAP_INDEX_PREFIX.sub("", name)
        m = elastic._BACKING_INDEX.match(bare)
        candidates = [name] + ([m.group("stream")] if m else [])
        for pattern, alias in self._indices.items():
            if any(fnmatch.fnmatchcase(c, pattern) for c in candidates):
                return alias or name
        raise Unmapped("index")

    def _cluster_in_name(self, name: Any) -> Any:
        if not isinstance(name, str):
            return name
        if name in self._cluster_in:
            return self._cluster_in[name]
        return name if self._clusters.get(name, "") is None else elastic.ALIAS_UNKNOWN

    def _index_in_name(self, name: Any) -> Any:
        if not isinstance(name, str):
            return name
        if name in self._index_in:
            return self._index_in[name]
        return name if self._indices.get(name, "") is None else elastic.ALIAS_UNKNOWN

    def _field_in_name(self, name: Any) -> Any:
        if not isinstance(name, str):
            return name
        if name in self._field_in:
            return self._field_in[name]
        rule = self.config.rule(name) if elastic._FIELD_RE.match(name) and "*" not in name else None
        if rule is not None and self._fields[rule.pattern] is None:
            return name
        return elastic.ALIAS_UNKNOWN

    # -- in ----------------------------------------------------------------

    def inbound(self, args: dict) -> dict:
        """A tool call's arguments with every alias put back. The shape is
        not judged here: the grammar refuses what it always refused."""
        out = self._fields_in(args)
        if "cluster" in out:
            out["cluster"] = self._cluster_in_name(out["cluster"])
        if "index" in out:
            out["index"] = self._index_in_name(out["index"])
        return out

    def _fields_in(self, node: Any) -> Any:
        if isinstance(node, dict):
            # "field" holds a name; an aggregation a session called "field"
            # holds an object, which is walked like any other
            return {k: (self._field_in_name(v) if k == "field" and isinstance(v, str)
                        else self._fields_in(v))
                    for k, v in node.items()}
        if isinstance(node, list):
            return [self._fields_in(v) for v in node]
        return node

    # -- out ---------------------------------------------------------------

    def summary(self, summary: dict) -> dict:
        """:meth:`hider.elastic.ElasticConfig.summary` in the names Claude
        may see."""
        out = dict(summary)
        out["indices"] = [self.index_out(i) for i in summary["indices"]]
        out["clusters"] = [self.cluster_out(c) for c in summary["clusters"]]
        out["fields"] = {self._fields[p] or p: kind for p, kind in summary["fields"].items()}
        out["time_field"] = self.field_out(summary["time_field"])
        return out

    def refusal(self, message: str) -> str:
        """A refusal names a rule and, sometimes, a field, an index or a
        cluster: those by alias. It never carries data."""
        if self._real_rx is None:
            return message
        return self._real_rx.sub(lambda m: self._real[m.group(0)], message)

    def prose(self, node: Any) -> Any:
        """The tools' own descriptions: fixed text of this program whose
        examples name a field (``agent.name``). Where the site aliases that
        field the example reads by alias, so Claude is never shown a name
        it would be refused for typing. Dotted names only: a one-word field
        name is also a word of the prose."""
        if isinstance(node, dict):
            return {k: self.prose(v) for k, v in node.items()}
        if isinstance(node, list):
            return [self.prose(v) for v in node]
        if isinstance(node, str) and self._real_rx is not None:
            return self._real_rx.sub(
                lambda m: self._real[m.group(0)] if "." in m.group(0) else m.group(0), node)
        return node

    def payload(self, payload: dict) -> dict:
        """A tool result with its structure renamed and its data untouched."""
        out = dict(payload)
        if isinstance(out.get("cluster"), str):
            out["cluster"] = self.cluster_out(out["cluster"])
        if isinstance(out.get("empty"), dict):
            out["empty"] = self._names(out["empty"])
        # hits stand at the top of a page and, under a top_hits, anywhere
        # inside the aggregations: every one is renamed, wherever it is
        for key in ("hits", "aggregations"):
            if key in out:
                out[key] = self._hits_in(out[key])
        return out

    def _hits_in(self, node: Any) -> Any:
        if isinstance(node, list):
            return [self._hits_in(v) for v in node]
        if not isinstance(node, dict):
            return node
        if "_source" in node or "_index" in node:
            return self._hit(node)
        return {k: self._hits_in(v) for k, v in node.items()}

    def _hit(self, hit: Any) -> Any:
        if not isinstance(hit, dict):
            return hit
        out = dict(hit)
        if isinstance(out.get("_index"), str):
            # the scrubber's marker class must not outlive the string
            out["_index"] = self.hit_index_out(str.__str__(out["_index"]))
        for section in ("_source", "fields"):
            if isinstance(out.get(section), dict):
                flat: dict[str, Any] = {}
                self._flatten(out[section], "", flat)
                out[section] = flat
        return out

    def _flatten(self, node: Any, path: str, out: dict[str, Any]) -> None:
        """``_source`` as one flat object keyed by alias (or by the dotted
        path where the site shows it as written). Objects inside a list
        keep the list's path, as the scrubber reads them."""
        if isinstance(node, dict):
            for k, v in node.items():
                self._flatten(v, f"{path}.{k}" if path else str(k), out)
            return
        if isinstance(node, list) and any(isinstance(x, (dict, list)) for x in node):
            for x in node:
                self._flatten(x, path, out)
            return
        name = self.field_out(path)
        if name in out:
            prev = out[name]
            out[name] = (prev if isinstance(prev, list) else [prev]) + [node]
        else:
            out[name] = node

    def _names(self, node: Any) -> Any:
        """The ``empty`` block: facts about fields, keyed and worded by
        field name, never a value."""
        if isinstance(node, dict):
            return {self.refusal(k) if isinstance(k, str) else k: self._names(v)
                    for k, v in node.items()}
        if isinstance(node, list):
            return [self._names(v) for v in node]
        if isinstance(node, str):
            return self.refusal(node)
        return node

    # -- for the engineer --------------------------------------------------

    def legend(self, text: str) -> list[tuple[str, str, str]]:
        """``(kind, alias, real name)`` for every alias that stands in
        ``text`` as a whole word: what the engineer needs beside an answer
        written in aliases. Never sent to a session."""
        found = []
        for kind, table in (("cluster", self._cluster_in), ("index", self._index_in),
                            ("field", self._field_in)):
            for alias, real in sorted(table.items()):
                if re.search(rf"(?<![\w.-]){re.escape(alias)}(?![\w-])", text):
                    found.append((kind, alias, real))
        return found
