# notifier.py — Telegram notification sender

from __future__ import annotations

import html
import time

import requests
import structlog

log = structlog.get_logger(__name__)


def _mask_token(token: str) -> str:
    return token[:8] + "..." if len(token) > 8 else "***"


class TelegramNotifier:
    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        rate_limit_seconds: float = 3.0,
        enabled: bool = True,
        proxy_url: str | None = None,
    ) -> None:
        self._bot_token = bot_token
        self._chat_id = chat_id
        self.rate_limit_seconds = rate_limit_seconds
        self.enabled = enabled
        self.proxy_url = proxy_url or None
        # float("-inf") means "never sent" — first call always passes through
        self._last_send: float = float("-inf")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _rate_limit(self) -> None:
        now = time.monotonic()
        wait = self.rate_limit_seconds - (now - self._last_send)
        if wait > 0:
            time.sleep(wait)
        self._last_send = time.monotonic()

    # ------------------------------------------------------------------
    # Core send
    # ------------------------------------------------------------------

    def notify(
        self,
        text: str,
        parse_mode: str = "HTML",
        silent: bool = False,
    ) -> bool:
        """Send *text* via Telegram sendMessage. Returns False on any failure."""
        if not self.enabled:
            log.info("notifier.disabled", preview=text[:60])
            return False

        self._rate_limit()

        url = f"https://api.telegram.org/bot{self._bot_token}/sendMessage"
        payload = {
            "chat_id": self._chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_notification": silent,
        }

        proxies = {"https": self.proxy_url} if self.proxy_url else None
        try:
            resp = requests.post(url, json=payload, proxies=proxies, timeout=10)
            if not resp.ok:
                log.warning(
                    "notifier.api_error",
                    status=resp.status_code,
                    body=resp.text[:200],
                    token=_mask_token(self._bot_token),
                )
                return False
            log.info("notifier.sent", chars=len(text), token=_mask_token(self._bot_token))
            return True
        except Exception as exc:
            log.warning(
                "notifier.network_error",
                error=str(exc),
                token=_mask_token(self._bot_token),
            )
            return False

    # ------------------------------------------------------------------
    # Typed helpers
    # ------------------------------------------------------------------

    def notify_success(
        self,
        ip: str,
        subnet: str,
        evidence: dict,
        stats: dict,
    ) -> bool:
        e = html.escape
        text = (
            "🎯 <b>Найден белый IP!</b>\n\n"
            f"🌐 <b>IP:</b> <code>{e(ip)}</code>\n"
            f"📡 <b>Подсеть:</b> <code>{e(subnet)}</code>\n\n"
            f"✅ ICMP: {e(str(evidence.get('icmp_alive', '?')))}"
            f"/{e(str(evidence.get('icmp_total', '?')))}\n"
            f"✅ TCP: {e(str(evidence.get('tcp_open', '?')))} портов открыто\n"
            f"✅ WLChecker: {e(str(evidence.get('wl_alive', '?')))}"
            f"/{e(str(evidence.get('wl_total', '?')))} alive\n\n"
            f"⏱ Время поиска: {e(str(stats.get('duration', '?')))}\n"
            f"🔍 Проверено подсетей: {e(str(stats.get('checked', '?')))}"
            f"/{e(str(stats.get('total', '?')))}"
        )
        return self.notify(text)

    def notify_warning(
        self,
        message: str,
        context: dict | None = None,
    ) -> bool:
        e = html.escape
        parts = [f"⚠️ <b>Предупреждение</b>\n\n{e(message)}"]
        if context:
            ctx_str = "\n".join(
                f"  {e(str(k))}: {e(str(v))}" for k, v in context.items()
            )
            parts.append(f"\n\n<pre>{ctx_str}</pre>")
        return self.notify("".join(parts))

    def notify_error(
        self,
        error: str,
        traceback: str | None = None,
    ) -> bool:
        e = html.escape
        text = f"❌ <b>Ошибка</b>\n\n{e(error)}"
        if traceback:
            text += f"\n\n<pre>{e(traceback[:1000])}</pre>"
        return self.notify(text)

    def notify_progress(self, stats: dict) -> bool:
        e = html.escape
        text = (
            "📊 <b>Прогресс поиска</b>\n"
            f"Проверено: {e(str(stats.get('checked', '?')))}"
            f"/{e(str(stats.get('total', '?')))}\n"
            f"Белых: {e(str(stats.get('white', '?')))}, "
            f"Мёртвых: {e(str(stats.get('dead', '?')))}, "
            f"Спорных: {e(str(stats.get('ambiguous', '?')))}\n"
            f"Текущая: <code>{e(str(stats.get('current_subnet', '')))}</code>\n"
            f"Время работы: {e(str(stats.get('elapsed', '?')))}"
        )
        return self.notify(text)


# ---------------------------------------------------------------------------
# CLI: python -m src.notifier --test "Hello"
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import os
    import sys

    from dotenv import load_dotenv

    load_dotenv()

    parser = argparse.ArgumentParser(description="TelegramNotifier test CLI")
    parser.add_argument("--test", metavar="MSG", help="Send a test message to the configured chat")
    args = parser.parse_args()

    if args.test:
        token = os.environ.get("TG_BOT_TOKEN")
        chat_id = os.environ.get("TG_CHAT_ID")

        if not token or not chat_id:
            print("Error: TG_BOT_TOKEN and TG_CHAT_ID must be set in .env")
            sys.exit(1)

        proxy_url = os.environ.get("TG_PROXY_URL") or None
        notifier = TelegramNotifier(bot_token=token, chat_id=chat_id, proxy_url=proxy_url)
        ok = notifier.notify(f"🔔 {args.test}")
        print("✅ Sent!" if ok else "❌ Failed — check logs above")
    else:
        parser.print_help()
