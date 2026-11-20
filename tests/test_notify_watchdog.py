"""notify_user forms, wait_for_user registration, watchdog classification."""

from __future__ import annotations

from pathlib import Path

from strix.agents import factory
from strix.core.watchdog import classify_log
from strix.notify import forms


def test_classify_out_of_credit() -> None:
    lines = ["x INFO ok", "x ERROR litellm: insufficient_quota: You exceeded your current quota"]
    kind, evidence = classify_log(lines)
    assert kind == "out_of_credit"
    assert "quota" in evidence


def test_classify_stalled_returns_log_tail() -> None:
    kind, evidence = classify_log(["a INFO fine", "b ERROR connection reset"])
    assert kind == "stalled"
    assert "connection reset" in evidence


def test_form_submit_is_one_time_and_strips_scripts(tmp_path: Path) -> None:
    record = forms.create_form(
        tmp_path,
        agent_id="agent-1",
        title="t",
        fields_html='<input name="code" onclick="x()"><script>alert(1)</script>',
        images=[],
        intro="hi",
    )
    page = forms.render_page(record)
    assert "<script" not in page.lower()
    assert "onclick" not in page.lower()
    values = forms.clean_values({"code": "1234"})
    assert forms.submit_form(tmp_path, record["id"], values) is not None
    assert forms.submit_form(tmp_path, record["id"], values) is None
    assert "1234" in forms.format_submission_message(forms.load_form(tmp_path, record["id"]) or {})


def test_wait_for_user_is_a_parking_tool() -> None:
    assert "wait_for_user" in factory._PARKING_TOOLS


def test_preset_forms_build_fields() -> None:
    html, _ = forms.build_fields("credentials", ["Username", "API key"], [], [])
    assert 'type="password"' in html
    assert 'name="Username"' in html
    html, rest = forms.build_fields("interactive", [], [], ["data:image/png;base64,AAAA"])
    assert 'type="image"' in html
    assert rest == []
    html, _ = forms.build_fields("decision", [], ["A", "B"], [])
    assert html.count('type="radio"') == 2
