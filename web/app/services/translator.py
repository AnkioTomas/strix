"""English report: LLM translates the prose fields, code assembles the report."""

from __future__ import annotations

import json
import logging
import zipfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from app.services.retest_report import render_retest_report

logger = logging.getLogger(__name__)

TRANSLATIONS_DIR = "translations"
EN_REPORT_MD = "penetration_test_report.en.md"
EN_REPORT_ZIP = "penetration_test_report.en.zip"

FINDING_FIELDS = (
    "title",
    "description",
    "impact",
    "poc_description",
    "remediation_steps",
    "manual_cleanup",
    "fix_verification",
)
SUMMARY_FIELDS = ("executive_summary", "methodology", "technical_analysis", "recommendations")

_SYSTEM_PROMPT = (
    "You translate parts of a penetration test report into English. "
    "Input is a JSON object of field name -> text. Return ONLY a JSON object with the "
    "same keys and the translated text. Keep Markdown structure, code blocks, URLs, "
    "payloads, commands, HTTP traffic, identifiers, file paths and image paths "
    "(images/...) exactly as they are; translate only the explanatory prose. "
    "Do not add, drop or reinterpret any fact."
)

Completion = Callable[[list[dict[str, str]]], str]


def _llm_completion() -> Completion:
    import litellm

    from strix.config import load_settings

    settings = load_settings()
    model = settings.report.translate_model or settings.llm.model
    if not model:
        raise RuntimeError("No LLM configured: set STRIX_TRANSLATE_MODEL or STRIX_LLM")

    def call(messages: list[dict[str, str]]) -> str:
        response = litellm.completion(
            model=model,
            messages=messages,
            api_key=settings.llm.api_key,
            api_base=settings.llm.api_base,
            extra_headers=settings.llm.extra_headers,
            temperature=0,
        )
        return str(response.choices[0].message.content or "")

    return call


def _parse_json_object(text: str) -> dict[str, Any]:
    body = text.strip()
    if body.startswith("```"):
        body = body.split("\n", 1)[1] if "\n" in body else ""
        body = body.rsplit("```", 1)[0]
    start, end = body.find("{"), body.rfind("}")
    if start < 0 or end < start:
        raise ValueError("translation reply is not a JSON object")
    data = json.loads(body[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("translation reply is not a JSON object")
    return data


def translate_fields(fields: dict[str, str], complete: Completion) -> dict[str, str]:
    """Translate non-empty fields; a malformed reply is retried once, then raises."""
    fields = {k: v for k, v in fields.items() if v.strip()}
    if not fields:
        return {}
    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(fields, ensure_ascii=False)},
    ]
    last: Exception | None = None
    for _ in range(2):
        try:
            data = _parse_json_object(complete(messages))
        except (ValueError, json.JSONDecodeError) as exc:
            last = exc
            continue
        return {k: str(data[k]) for k in fields if isinstance(data.get(k), str) and data[k].strip()}
    raise RuntimeError(f"translation failed: {last}")


def _finding_id(finding: dict[str, Any]) -> str:
    return str(finding.get("id") or finding.get("report_id") or "")


def translate_run(
    findings: list[dict[str, Any]],
    scan_results: dict[str, Any] | None,
    complete: Completion,
) -> dict[str, Any]:
    """``{"findings": {id: {field: text}}, "summary": {field: text}}``."""

    def one(finding: dict[str, Any]) -> tuple[str, dict[str, str]]:
        src = {f: str(finding.get(f) or "") for f in FINDING_FIELDS}
        return _finding_id(finding), translate_fields(src, complete)

    with ThreadPoolExecutor(max_workers=4) as pool:
        translated = dict(pool.map(one, findings))
    summary_src = {f: str((scan_results or {}).get(f) or "") for f in SUMMARY_FIELDS}
    return {"findings": translated, "summary": translate_fields(summary_src, complete)}


def apply_translations(
    findings: list[dict[str, Any]],
    scan_results: dict[str, Any] | None,
    translations: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    by_id = translations.get("findings") or {}
    out = [{**f, **(by_id.get(_finding_id(f)) or {})} for f in findings]
    summary = {**(scan_results or {}), **(translations.get("summary") or {})} if scan_results else None
    return out, summary


def write_english_report(
    run_dir: Path,
    *,
    run_record: dict[str, Any],
    findings: list[dict[str, Any]],
    scan_results: dict[str, Any] | None,
    translations: dict[str, Any],
    retest: bool = False,
    scope_ids: set[str] | None = None,
) -> Path:
    """Render the English report from translated fields and zip it with screenshots."""
    from strix.report.locale import chrome_language
    from strix.report.zh_report import render_zh_penetration_report

    findings, scan_results = apply_translations(findings, scan_results, translations)
    if retest:
        md = render_retest_report(
            run_record=run_record,
            vulnerability_reports=findings,
            scan_results=scan_results,
            lang="en",
            scope_ids=scope_ids,
        )
    else:
        with chrome_language("en"):
            md = render_zh_penetration_report(
                run_record=run_record,
                vulnerability_reports=findings,
                scan_results=scan_results,
            )
    md_path = run_dir / EN_REPORT_MD
    md_path.write_text(md, encoding="utf-8")
    zip_path = run_dir / EN_REPORT_ZIP
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(md_path, arcname=md_path.name)
        images = run_dir / "images"
        if images.is_dir():
            for image in sorted(images.iterdir()):
                if image.is_file():
                    zf.write(image, arcname=f"images/{image.name}")
    return md_path


def translate_report(
    run_dir: Path,
    *,
    run_record: dict[str, Any],
    findings: list[dict[str, Any]],
    scan_results: dict[str, Any] | None,
    retest: bool = False,
    scope_ids: set[str] | None = None,
    complete: Completion | None = None,
) -> Path:
    translations = translate_run(findings, scan_results, complete or _llm_completion())
    out_dir = run_dir / TRANSLATIONS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "en.json").write_text(
        json.dumps(translations, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return write_english_report(
        run_dir,
        run_record=run_record,
        findings=findings,
        scan_results=scan_results,
        translations=translations,
        retest=retest,
        scope_ids=scope_ids,
    )
