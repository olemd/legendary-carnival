"""Runs rules, applies config overrides, persists findings."""

from __future__ import annotations

import importlib
import logging
import pkgutil
from dataclasses import dataclass, field

from lanwatch import rules as rules_pkg
from lanwatch.config import Config
from lanwatch.models import Finding
from lanwatch.rules.base import Rule, RuleContext

log = logging.getLogger(__name__)

# The modules that existed before rules were found by scanning, in their old order, so
# the list (and everything that shows it) stays as it was. Any other module in
# lanwatch.rules with a RULES list follows, by module name: a new rule file needs no
# edit here.
_FIRST = ("inventory", "services", "versions", "infra", "unifi", "airos", "ids")
_NOT_RULES = {"base", "engine"}


def all_rules() -> list[Rule]:
    names = {m.name for m in pkgutil.iter_modules(rules_pkg.__path__)} - _NOT_RULES
    ordered = [n for n in _FIRST if n in names] + sorted(names - set(_FIRST))
    out: list[Rule] = []
    seen: set[str] = set()
    for name in ordered:
        module = importlib.import_module(f"{rules_pkg.__name__}.{name}")
        for rule in getattr(module, "RULES", []):
            if rule.id in seen:
                raise RuntimeError(f"two rules with the id {rule.id!r}")
            seen.add(rule.id)
            out.append(rule)
    return out


@dataclass(slots=True)
class RunResult:
    emitted: list[Finding] = field(default_factory=list)
    new_ids: list[str] = field(default_factory=list)
    resolved_ids: list[str] = field(default_factory=list)
    skipped_rules: list[str] = field(default_factory=list)


class Engine:
    def __init__(self, config: Config, rules: list[Rule] | None = None) -> None:
        self.config = config
        self.rules = rules if rules is not None else all_rules()

    def enabled_rules(self) -> list[Rule]:
        out: list[Rule] = []
        for r in self.rules:
            o = self.config.rules.get(r.id)
            if o is not None and o.enabled is False:
                continue
            out.append(r)
        return out

    def run(self, ctx: RuleContext) -> RunResult:
        result = RunResult()
        ran: set[str] = set()
        auto: set[str] = set()
        for rule in self.rules:
            override = self.config.rules.get(rule.id)
            if override is not None and override.enabled is False:
                result.skipped_rules.append(rule.id)
                continue
            try:
                findings = rule.evaluate(ctx)
            except Exception:
                log.exception("rule %s failed", rule.id)
                continue
            ran.add(rule.id)
            if rule.auto_resolve:
                auto.add(rule.id)
            if override is not None and override.severity is not None:
                findings = [f.model_copy(update={"severity": override.severity}) for f in findings]
            result.emitted.extend(findings)
        result.new_ids, result.resolved_ids = ctx.store.upsert_findings(result.emitted, ran, auto)
        return result
