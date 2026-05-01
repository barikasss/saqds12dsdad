import json
from unittest.mock import patch

import pytest
import requests
import responses as resp_lib

from src.notifier import TelegramNotifier

TOKEN = "supersecret_bot_token_abc123"
CHAT_ID = "-100987654321"
TG_URL = f"https://api.telegram.org/bot{TOKEN}/sendMessage"


def make_notifier(**kwargs) -> TelegramNotifier:
    defaults = dict(
        bot_token=TOKEN,
        chat_id=CHAT_ID,
        rate_limit_seconds=0.0,  # no rate limit in most tests
        enabled=True,
    )
    defaults.update(kwargs)
    return TelegramNotifier(**defaults)


# ---------------------------------------------------------------------------
# 1. test_notify_success_call
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_notify_success_call():
    resp_lib.add(resp_lib.POST, TG_URL, json={"ok": True, "result": {"message_id": 1}})

    notifier = make_notifier()
    ok = notifier.notify_success(
        ip="1.2.3.4",
        subnet="1.2.3.0/24",
        evidence={
            "icmp_alive": 13, "icmp_total": 254,
            "tcp_open": 5,
            "wl_alive": 11, "wl_total": 254,
        },
        stats={"duration": "1m 30s", "checked": 42, "total": 1000},
    )

    assert ok is True
    assert len(resp_lib.calls) == 1

    body = json.loads(resp_lib.calls[0].request.body)
    assert body["chat_id"] == CHAT_ID
    assert body["parse_mode"] == "HTML"
    text = body["text"]
    assert "1.2.3.4" in text
    assert "1.2.3.0/24" in text
    assert "13/254" in text
    assert "1m 30s" in text
    assert "42/1000" in text


# ---------------------------------------------------------------------------
# 2. test_html_escape
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_html_escape():
    resp_lib.add(resp_lib.POST, TG_URL, json={"ok": True})

    notifier = make_notifier()
    notifier.notify_success(
        ip="<b>1.2.3.4</b>",
        subnet="1.2.3.0/24",
        evidence={
            "icmp_alive": "<script>xss</script>", "icmp_total": 254,
            "tcp_open": 5, "wl_alive": 11, "wl_total": 254,
        },
        stats={"duration": "test & <bold>", "checked": 1, "total": 10},
    )

    text = json.loads(resp_lib.calls[0].request.body)["text"]

    # Raw tags must NOT pass through
    assert "<b>1.2.3.4</b>" not in text
    assert "<script>" not in text

    # Escaped forms must be present
    assert "&lt;b&gt;1.2.3.4&lt;/b&gt;" in text
    assert "&lt;script&gt;xss&lt;/script&gt;" in text
    assert "test &amp; &lt;bold&gt;" in text


# ---------------------------------------------------------------------------
# 3. test_rate_limit
# ---------------------------------------------------------------------------

def test_rate_limit():
    # Four time.monotonic() calls in _rate_limit:
    #   notify-1 "now":        0.0  → elapsed=inf → no sleep
    #   notify-1 _last_send:   0.1
    #   notify-2 "now":        0.5  → elapsed=0.4 → sleep(3.0-0.4=2.6)
    #   notify-2 _last_send:   3.5
    times = iter([0.0, 0.1, 0.5, 3.5])
    sleep_calls: list[float] = []

    with patch("src.notifier.time") as mock_time:
        mock_time.monotonic.side_effect = lambda: next(times)
        mock_time.sleep.side_effect = lambda s: sleep_calls.append(s)

        with resp_lib.RequestsMock() as rsps:
            rsps.add(resp_lib.POST, TG_URL, json={"ok": True})
            rsps.add(resp_lib.POST, TG_URL, json={"ok": True})

            notifier = TelegramNotifier(TOKEN, CHAT_ID, rate_limit_seconds=3.0)
            notifier.notify("first")
            notifier.notify("second")

    assert len(sleep_calls) == 1
    assert sleep_calls[0] == pytest.approx(2.6, abs=0.05)


# ---------------------------------------------------------------------------
# 4. test_disabled_no_op
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_disabled_no_op():
    notifier = make_notifier(enabled=False)
    result = notifier.notify("should not be sent")

    assert result is False
    assert len(resp_lib.calls) == 0  # no HTTP calls made


# ---------------------------------------------------------------------------
# 5. test_network_error_no_raise
# ---------------------------------------------------------------------------

@resp_lib.activate
def test_network_error_no_raise():
    resp_lib.add(
        resp_lib.POST,
        TG_URL,
        body=requests.ConnectionError("connection refused"),
    )

    notifier = make_notifier()
    result = notifier.notify("hello")  # must NOT raise

    assert result is False


# ---------------------------------------------------------------------------
# 6. test_token_masked_in_logs
# ---------------------------------------------------------------------------

def test_token_masked_in_logs():
    from structlog.testing import capture_logs

    with capture_logs() as cap:
        with resp_lib.RequestsMock() as rsps:
            rsps.add(resp_lib.POST, TG_URL, json={"ok": True})
            notifier = make_notifier()
            notifier.notify("hello")

    for event in cap:
        for v in event.values():
            assert TOKEN not in str(v), f"Bot token leaked in log event: {event}"


# ---------------------------------------------------------------------------
# 7. test_notifier_with_proxy
# ---------------------------------------------------------------------------

def test_notifier_with_proxy():
    from unittest.mock import patch, call

    proxy = "socks5://127.0.0.1:10808"
    notifier = make_notifier(proxy_url=proxy)

    with patch("src.notifier.requests.post") as mock_post:
        mock_post.return_value.ok = True
        notifier.notify("hello proxy")

    _, kwargs = mock_post.call_args
    assert kwargs["proxies"] == {"https": proxy}


def test_notifier_no_proxy_when_none():
    from unittest.mock import patch

    notifier = make_notifier(proxy_url=None)

    with patch("src.notifier.requests.post") as mock_post:
        mock_post.return_value.ok = True
        notifier.notify("no proxy")

    _, kwargs = mock_post.call_args
    assert kwargs["proxies"] is None
