"""Send the delivery report package by SMTP."""

from __future__ import annotations

import base64
import smtplib
import socket
import ssl
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import unquote, urlsplit

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

    _deliver(settings, message, sender=sender, recipients=[*to, *cc])


def _deliver(
    settings: Settings, message: EmailMessage, *, sender: str, recipients: list[str]
) -> None:
    host, port = settings.smtp_host.strip(), settings.smtp_port
    proxy = settings.smtp_proxy.strip()
    try:
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
    except (OSError, smtplib.SMTPException, MailError) as exc:
        raise MailError(f"邮件发送失败：{exc}") from exc


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
    message.set_content(
        f"这是一封测试邮件。收到说明 SMTP 配置正确：{smtp_target(settings)}\n"
    )
    _deliver(settings, message, sender=sender, recipients=to)
