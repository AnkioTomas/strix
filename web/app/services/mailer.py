"""Send the delivery report package by SMTP."""

from __future__ import annotations

import base64
import logging
import smtplib
import socket
import ssl
import time
from email.message import EmailMessage
import re
from datetime import datetime
from html import escape
from pathlib import Path
from urllib.parse import unquote, urlsplit

from app.config import Settings


logger = logging.getLogger(__name__)


class MailError(RuntimeError):
    pass


_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def parse_emails(value: object) -> list[str]:
    """Split a CSV/list of addresses; raises ValueError on a malformed one."""
    if value is None:
        return []
    parts = (
        re.split(r"[,;，；\s]+", value) if isinstance(value, str) else [str(v) for v in value]
    )
    emails: list[str] = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if not _EMAIL.match(part):
            raise ValueError(f"通知邮箱格式不正确：{part}")
        if part not in emails:
            emails.append(part)
    return emails


_SEVERITY_LABELS = (
    ("critical", "严重"),
    ("high", "高危"),
    ("medium", "中危"),
    ("low", "低危"),
    ("info", "信息"),
)
_FIX_LABELS = {
    "fixed": "已修复",
    "not_fixed": "未修复",
    "partial": "部分修复",
    "regressed": "复现",
    "open": "未复测",
}
_FIX_COLORS = {
    "fixed": ("#166534", "#dcfce7"),
    "not_fixed": ("#991b1b", "#fee2e2"),
    "partial": ("#9a3412", "#ffedd5"),
    "regressed": ("#991b1b", "#fee2e2"),
    "open": ("#475569", "#e2e8f0"),
}
_LISTED_SEVERITIES = 3  # 严重 / 高危 / 中危


_SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#64748b",
}
_DEFAULT_TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "mail_report.html"


def _load_html_template(settings: Settings) -> str:
    custom = settings.mail_html_file.strip()
    path = Path(custom).expanduser() if custom else _DEFAULT_TEMPLATE
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MailError(f"无法读取邮件 HTML 模板 {path}：{exc}") from exc


def build_report_html(
    settings: Settings,
    *,
    subject: str,
    title: str,
    target: str,
    counts: dict[str, object],
    findings: list[dict[str, object]],
    bu: str = "",
    owner: str = "",
    task_id: str = "",
    retest: bool = False,
) -> str:
    """Render the HTML mail. ``{{key}}`` placeholders; text values are escaped."""
    n = {key: int(counts.get(key) or 0) for key, _ in _SEVERITY_LABELS}
    total = int(counts.get("total") or sum(n.values()))
    serious_total = n["critical"] + n["high"]
    if n["critical"]:
        accent, headline = "#b91c1c", f"发现 {serious_total} 个严重 / 高危漏洞，请优先处理"
    elif n["high"]:
        accent, headline = "#ea580c", f"发现 {serious_total} 个高危漏洞，请尽快处理"
    elif total:
        accent, headline = "#2563eb", f"共发现 {total} 个漏洞，未发现严重 / 高危漏洞"
    else:
        accent, headline = "#16a34a", "未发现漏洞"

    cards = "".join(
        f'<td align="center" style="background:#f8fafc;border:1px solid #e5e7eb;'
        f'border-top:3px solid {_SEVERITY_COLORS[key]};border-radius:8px;padding:12px 4px;">'
        f'<div style="font-size:26px;font-weight:700;color:{_SEVERITY_COLORS[key]};line-height:1.2;">{n[key]}</div>'
        f'<div style="font-size:12px;color:#6b7280;margin-top:2px;">{label}</div></td>'
        for key, label in _SEVERITY_LABELS
    )

    info = [("测试目标", target), ("所属 BU", bu), ("负责人", owner)]
    info_rows = "".join(
        f'<tr><td width="110" style="padding:10px 14px;color:#6b7280;border-bottom:1px solid #f1f5f9;">{k}</td>'
        f'<td style="padding:10px 14px;border-bottom:1px solid #f1f5f9;word-break:break-all;">{escape(v)}</td></tr>'
        for k, v in info
        if v
    )

    rows = []
    fix_counts: dict[str, int] = {}
    for key, label in _SEVERITY_LABELS[:_LISTED_SEVERITIES]:
        for item in findings:
            if item.get("severity") != key:
                continue
            status = str(item.get("fix_status") or "open")
            badge = ""
            if retest and status in _FIX_LABELS:
                fix_counts[status] = fix_counts.get(status, 0) + 1
                color, background = _FIX_COLORS[status]
                badge = (
                    f'<span style="font-size:12px;font-weight:600;color:{color};'
                    f'background:{background};border-radius:4px;padding:2px 8px;'
                    f'white-space:nowrap;">{_FIX_LABELS[status]}</span>'
                )
            rows.append(
                f'<tr><td width="64" style="padding:10px 12px;border-bottom:1px solid #f1f5f9;">'
                f'<span style="background:{_SEVERITY_COLORS[key]};color:#fff;border-radius:4px;'
                f'padding:2px 8px;font-size:12px;">{label}</span></td>'
                f'<td style="padding:10px 12px;border-bottom:1px solid #f1f5f9;font-size:14px;line-height:1.5;">'
                f'{escape(str(item.get("title") or "未命名"))}</td>'
                + (
                    f'<td width="76" align="right" style="padding:10px 12px;border-bottom:1px solid #f1f5f9;">{badge}</td>'
                    if retest
                    else ""
                )
                + "</tr>"
            )
    others = sum(n[key] for key, _ in _SEVERITY_LABELS[_LISTED_SEVERITIES:])
    more = f"另有 {others} 个低危 / 信息级漏洞，详见报告。" if others else ""
    fix_summary = (
        "复测结果：" + "，".join(
            f"{_FIX_LABELS[key]} {fix_counts[key]}" for key in _FIX_LABELS if fix_counts.get(key)
        )
        if retest and fix_counts
        else ""
    )
    note_style = "font-size:13px;color:#6b7280;margin-top:10px;"
    serious_section = (
        '<tr><td style="padding:24px 32px 0 32px;">'
        '<div style="font-size:16px;font-weight:700;margin-bottom:12px;">'
        "漏洞清单<span style=\"font-weight:400;color:#6b7280;font-size:13px;\">（严重 / 高危 / 中危）</span></div>"
        + (f'<div style="font-size:14px;margin-bottom:12px;">{escape(fix_summary)}</div>' if fix_summary else "")
        + '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="border:1px solid #e5e7eb;border-radius:8px;">'
        + "".join(rows)
        + "</table>"
        + (f'<div style="{note_style}">{escape(more)}</div>' if more else "")
        + "</td></tr>"
        if rows
        else ""
    )

    advice = (
        "建议先处理上方严重 / 高危问题，修复后可申请复测确认。"
        if serious_total
        else "详细的漏洞描述、复现步骤与修复建议请见报告。"
    )
    intro = (
        f"「{escape(title)}」的{'复测' if retest else '安全测试'}已完成，结果概览如下。"
    )
    values = {
        "subject": escape(subject),
        "title": escape(title),
        "accent": accent,
        "headline": escape(headline),
        "intro": intro,
        "info_rows": info_rows,
        "total": str(total),
        "severity_cards": cards,
        "serious_section": serious_section,
        "advice": escape(advice),
        "task_id": escape(task_id or "-"),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
    return re.sub(
        r"\{\{(\w+)\}\}",
        lambda m: values.get(m.group(1), m.group(0)),
        _load_html_template(settings),
    )


def sample_report_html(settings: Settings) -> str:
    return build_report_html(
        settings,
        subject="【安全测试报告】示例应用（demo.example.com:8443）",
        title="示例应用（demo.example.com:8443）",
        target="https://demo.example.com:8443",
        counts={"total": 9, "critical": 1, "high": 2, "medium": 3, "low": 2, "info": 1},
        findings=[
            {"severity": "critical", "title": "登录接口存在 SQL 注入，可读取全部用户数据"},
            {"severity": "high", "title": "订单详情接口越权访问（IDOR）", "fix_status": "not_fixed"},
            {"severity": "high", "title": "文件上传未校验类型导致任意文件上传", "fix_status": "fixed"},
            {"severity": "medium", "title": "会话 Cookie 未设置 Secure / HttpOnly", "fix_status": "partial"},
            {"severity": "medium", "title": "接口返回详细错误堆栈", "fix_status": "open"},
        ],
        retest=True,
        bu="YFI",
        owner="owner@example.com",
        task_id="demo-0001",
    )


class _Safe(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def render_template(template: str, values: dict[str, object]) -> str:
    """``str.format`` that leaves unknown placeholders and stray braces alone."""
    text = template.replace("\\n", "\n")
    try:
        return text.format_map(_Safe(values))
    except (ValueError, IndexError, AttributeError):
        return text


def _tunnel(proxy_url: str, host: str, port: int, timeout: float) -> socket.socket:
    """TCP tunnel to ``host:port`` through an HTTP proxy (CONNECT)."""
    parts = urlsplit(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
    if parts.scheme != "http" or not parts.hostname:
        raise MailError("STRIX_SMTP_PROXY 仅支持 http://host:port")
    sock = socket.create_connection((parts.hostname, parts.port or 80), timeout=timeout)
    try:
        request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        if parts.username:
            cred = f"{unquote(parts.username)}:{unquote(parts.password or '')}"
            request += f"Proxy-Authorization: Basic {base64.b64encode(cred.encode()).decode()}\r\n"
        sock.sendall((request + "\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk or len(head) > 65536:
                raise MailError("代理连接被提前关闭")
            head += chunk
        status = head.split(b"\r\n", 1)[0].decode("latin-1")
        if len(status.split()) < 2 or status.split()[1] != "200":
            raise MailError(f"代理拒绝连接 {host}:{port}（{status}），请确认代理策略放行该端口")
    except BaseException:
        sock.close()
        raise
    return sock


class _ProxySMTP(smtplib.SMTP):
    def __init__(self, *args: object, proxy: str, **kwargs: object) -> None:
        self._proxy = proxy
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        return _tunnel(self._proxy, host, port, timeout)


class _ProxySMTPSSL(smtplib.SMTP_SSL):
    def __init__(self, *args: object, proxy: str, **kwargs: object) -> None:
        self._proxy = proxy
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        return self.context.wrap_socket(
            _tunnel(self._proxy, host, port, timeout), server_hostname=self._host
        )


def mail_enabled(settings: Settings) -> bool:
    return bool(settings.smtp_host.strip())


def send_report_mail(
    settings: Settings,
    *,
    to: list[str],
    subject: str,
    html: str,
    attachment: Path,
    attachment_name: str,
    high_priority: bool = False,
) -> None:
    if not mail_enabled(settings):
        raise MailError("未配置 STRIX_SMTP_HOST，无法发送邮件")
    sender = settings.smtp_from.strip() or settings.smtp_user.strip()
    if not sender:
        raise MailError("未配置 STRIX_SMTP_FROM / STRIX_SMTP_USER")
    cc = [addr for addr in settings.mail_cc_list() if addr not in to]
    if not to and not cc:
        raise MailError("没有收件人")

    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(to) if to else ", ".join(cc)
    if to and cc:
        message["Cc"] = ", ".join(cc)
    message["Subject"] = subject
    if high_priority:
        message["Importance"] = "High"
        message["X-Priority"] = "1 (Highest)"
        message["X-MSMail-Priority"] = "High"
    message.set_content(html, subtype="html")
    subtype = Path(attachment_name).suffix.lstrip(".").lower() or "octet-stream"
    message.add_attachment(
        attachment.read_bytes(),
        maintype="application",
        subtype=subtype,
        filename=attachment_name,
    )

    # Gateways drop oversize mail silently or bounce it after the fact; a
    # doomed send also wastes the retry budget. Fail here, where the caller
    # records mail_status=failed and fires the mail_failed webhook.
    size_mb = len(message.as_bytes()) / (1024 * 1024)
    if size_mb > settings.mail_max_mb:
        raise MailError(
            f"报告邮件约 {size_mb:.1f}MB，超过上限 {settings.mail_max_mb}MB"  # noqa: RUF001
            "（STRIX_MAIL_MAX_MB），已停止发送，请在控制台下载报告后手动转发"  # noqa: RUF001
        )

    _deliver(settings, message, sender=sender, recipients=[*to, *cc])


_DELIVER_ATTEMPTS = 5
# Exponential backoff between attempts: 5s, 10s, 20s, 40s.
_DELIVER_RETRY_DELAYS = (5.0, 10.0, 20.0, 40.0)


def _is_transient_smtp_error(exc: BaseException) -> bool:
    """Whether another attempt can plausibly succeed.

    4xx replies and dropped connections are transient; 5xx replies (bad
    credentials, refused recipients) and local config/proxy errors are not.
    """
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return False
    if isinstance(exc, smtplib.SMTPResponseException):
        return 400 <= exc.smtp_code < 500
    return isinstance(exc, (OSError, smtplib.SMTPException))


def _deliver(
    settings: Settings, message: EmailMessage, *, sender: str, recipients: list[str]
) -> None:
    for attempt in range(_DELIVER_ATTEMPTS):
        try:
            _deliver_once(settings, message, sender=sender, recipients=recipients)
        except (OSError, smtplib.SMTPException, MailError) as exc:
            if attempt + 1 >= _DELIVER_ATTEMPTS or not _is_transient_smtp_error(exc):
                raise MailError(f"邮件发送失败：{exc}") from exc
            delay = _DELIVER_RETRY_DELAYS[min(attempt, len(_DELIVER_RETRY_DELAYS) - 1)]
            logger.warning(
                "mail delivery attempt %d/%d failed: %s; retrying in %.0fs",
                attempt + 1,
                _DELIVER_ATTEMPTS,
                exc,
                delay,
            )
            time.sleep(delay)
        else:
            return


def _deliver_once(
    settings: Settings, message: EmailMessage, *, sender: str, recipients: list[str]
) -> None:
    host, port = settings.smtp_host.strip(), settings.smtp_port
    proxy = settings.smtp_proxy.strip()
    if settings.smtp_ssl:
        context = ssl.create_default_context()
        client: smtplib.SMTP = (
            _ProxySMTPSSL(host, port, timeout=60, context=context, proxy=proxy)
            if proxy
            else smtplib.SMTP_SSL(host, port, timeout=60, context=context)
        )
    else:
        client = (
            _ProxySMTP(host, port, timeout=60, proxy=proxy)
            if proxy
            else smtplib.SMTP(host, port, timeout=60)
        )
    with client:
        if not settings.smtp_ssl and client.has_extn("starttls"):
            client.starttls(context=ssl.create_default_context())
        if settings.smtp_user:
            client.login(settings.smtp_user, settings.smtp_password)
        client.send_message(message, from_addr=sender, to_addrs=recipients)


def smtp_target(settings: Settings) -> str:
    proxy = " 经代理" if settings.smtp_proxy.strip() else ""
    mode = "SSL" if settings.smtp_ssl else "STARTTLS/明文"
    return f"{settings.smtp_host.strip()}:{settings.smtp_port}（{mode}{proxy}）"


def send_test_mail(settings: Settings, *, to: list[str]) -> None:
    """Send a tiny message through the same path as report mails (proxy, TLS, login)."""
    if not mail_enabled(settings):
        raise MailError("未配置 STRIX_SMTP_HOST，无法发送邮件")
    sender = settings.smtp_from.strip() or settings.smtp_user.strip()
    if not sender:
        raise MailError("未配置 STRIX_SMTP_FROM / STRIX_SMTP_USER")
    if not to:
        raise MailError("没有收件人")
    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(to)
    message["Subject"] = "【Strix】邮件发送测试"
    message.set_content(sample_report_html(settings), subtype="html")
    _deliver(settings, message, sender=sender, recipients=to)
