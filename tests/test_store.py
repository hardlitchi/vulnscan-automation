from datetime import date

from vulnscan.models import Finding
from vulnscan.store import Store
from vulnscan.suppressions import Suppression, split_suppressed


def f(rule, loc="https://a/", tool="nuclei", sev="high"):
    return Finding(tool=tool, rule_id=rule, title=rule, severity=sev, target="T", location=loc)


def test_diff_new_persisting_fixed(tmp_path):
    s = Store(tmp_path / "db.sqlite")
    r1 = s.start_run("T", "standard", "A", ["nuclei"])
    d1 = s.record(r1, "T", ["nuclei"], [f("a"), f("b")])
    assert {x.rule_id for x in d1.new} == {"a", "b"}

    r2 = s.start_run("T", "standard", "A", ["nuclei"])
    d2 = s.record(r2, "T", ["nuclei"], [f("b"), f("c")])
    assert [x.rule_id for x in d2.new] == ["c"]
    assert [x.rule_id for x in d2.persisting] == ["b"]
    assert [x.rule_id for x in d2.fixed] == ["a"]

    # 解消後に再発したものは新規扱い
    r3 = s.start_run("T", "standard", "A", ["nuclei"])
    d3 = s.record(r3, "T", ["nuclei"], [f("a"), f("b"), f("c")])
    assert [x.rule_id for x in d3.new] == ["a"]

    stored = s.run_diff(r2)
    assert {x.rule_id for x in stored.fixed} == {"a"}
    s.close()


def test_failed_tool_does_not_mark_fixed(tmp_path):
    s = Store(tmp_path / "db.sqlite")
    r1 = s.start_run("T", "standard", "A", ["nuclei", "zap"])
    s.record(r1, "T", ["nuclei", "zap"], [f("a"), f("z", tool="zap")])
    r2 = s.start_run("T", "standard", "A", ["nuclei", "zap"])
    d2 = s.record(r2, "T", ["nuclei"], [f("a")])  # zap が失敗
    assert d2.fixed == []


def test_other_target_not_affected(tmp_path):
    s = Store(tmp_path / "db.sqlite")
    s.record(s.start_run("T", "p", "A", ["nuclei"]), "T", ["nuclei"], [f("a")])
    other = Finding(
        tool="nuclei", rule_id="x", title="x", severity="low", target="U", location="https://u/"
    )
    d = s.record(s.start_run("U", "p", "A", ["nuclei"]), "U", ["nuclei"], [other])
    assert d.fixed == []


def test_suppressions_respect_expiry():
    rules = [
        Suppression(reason="fp", status="false_positive", expires=date(2026, 12, 31), rule_id="a")
    ]
    kept, sup = split_suppressed([f("a"), f("b")], rules, today=date(2026, 10, 7))
    assert [x.rule_id for x in kept] == ["b"]
    assert sup[0][1].reason == "fp"
    kept, sup = split_suppressed([f("a")], rules, today=date(2027, 1, 1))
    assert len(kept) == 1 and not sup


def test_severity_normalization():
    assert f("x", sev="Informational").severity == "info"
    assert f("x", sev="weird").severity == "info"
    assert f("x", sev="CRITICAL").severity == "critical"


def test_list_runs_counts_exclude_info(tmp_path):
    s = Store(tmp_path / "db.sqlite")
    r = s.start_run("T", "standard", "A", ["nuclei"])
    s.record(r, "T", ["nuclei"], [f("a"), f("b", sev="info")])
    s.finish_run(r, "completed")
    [row] = s.list_runs()
    assert (row["new"], row["open"], row["fixed"], row["status"]) == (1, 1, 0, "completed")
    assert [x.rule_id for x in s.open_findings()] in (["a", "b"], ["b", "a"])
