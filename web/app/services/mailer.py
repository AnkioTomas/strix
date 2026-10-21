"""Send the delivery report package by SMTP."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

from app.config import Settings


class MailError(RuntimeError):
    pass


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


def mail_enabled(settings: Settings) -> bool:
    return bool(settings.smtp_host.strip())


def send_report_mail(
    settings: Settings,
    *,
    to: list[str],
    subject: str,
    body: str,
    attachment: Path,
    attachment_name: str,
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
    message.set_content(body)
    message.add_attachment(
        attachment.read_bytes(),
        maintype="application",
        subtype="zip",
        filename=attachment_name,
    )

    host, port = settings.smtp_host.strip(), settings.smtp_port
    try:
        if settings.smtp_ssl:
            client: smtplib.SMTP = smtplib.SMTP_SSL(
                host, port, timeout=60, context=ssl.create_default_context()
            )
        else:
            client = smtplib.SMTP(host, port, timeout=60)
        with client:
            if not settings.smtp_ssl and client.has_extn("starttls"):
                client.starttls(context=ssl.create_default_context())
            if settings.smtp_user:
                client.login(settings.smtp_user, settings.smtp_password)
            client.send_message(message, from_addr=sender, to_addrs=[*to, *cc])
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError(f"邮件发送失败：{exc}") from exc
