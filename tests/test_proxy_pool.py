"""Tests for ProxyPool — round-robin + cooldown."""

from unittest.mock import patch

import pytest

from src.proxy_pool import ProxyPool, _mask


PROXIES = [
    "socks5://1.2.3.4:1080",
    "socks5://5.6.7.8:1080",
    "socks5://9.10.11.12:1080",
]


def test_get_returns_first_available():
    pool = ProxyPool(proxies=PROXIES, cooldown_seconds=120)
    result = pool.get()
    assert result == PROXIES[0]


def test_all_three_available_before_any_release():
    pool = ProxyPool(proxies=PROXIES, cooldown_seconds=120)
    # All three have never been released → all have elapsed cooldown (last=0)
    results = {pool.get() for _ in range(3)}
    # get() always returns the first eligible — same proxy until released
    assert len(results) == 1
    assert results == {PROXIES[0]}


def test_release_puts_in_cooldown():
    pool = ProxyPool(proxies=PROXIES, cooldown_seconds=120)
    p = pool.get()
    assert p == PROXIES[0]
    pool.release(p)

    # First proxy is now in cooldown → next get() returns second
    p2 = pool.get()
    assert p2 == PROXIES[1]


def test_all_released_returns_none():
    pool = ProxyPool(proxies=PROXIES, cooldown_seconds=120)
    for p in PROXIES:
        pool.release(p)
    assert pool.get() is None


def test_cooldown_expires():
    pool = ProxyPool(proxies=["socks5://1.2.3.4:1080"], cooldown_seconds=1)
    pool.release("socks5://1.2.3.4:1080")
    assert pool.get() is None

    # Fake time passing cooldown
    with patch("src.proxy_pool.time") as mock_time:
        mock_time.time.return_value = pool._released_at["socks5://1.2.3.4:1080"] + 2
        result = pool.get()
    assert result == "socks5://1.2.3.4:1080"


def test_next_available_in_zero_when_free():
    pool = ProxyPool(proxies=PROXIES, cooldown_seconds=120)
    assert pool.next_available_in() == 0.0


def test_next_available_in_positive_when_all_busy():
    pool = ProxyPool(proxies=PROXIES, cooldown_seconds=120)
    for p in PROXIES:
        pool.release(p)
    wait = pool.next_available_in()
    assert 0 < wait <= 120


def test_empty_pool():
    pool = ProxyPool(proxies=[], cooldown_seconds=120)
    assert pool.get() is None
    assert pool.next_available_in() == 0.0


def test_from_env():
    env = "socks5://a:b@1.2.3.4:1080, socks5://c:d@5.6.7.8:1080"
    pool = ProxyPool.from_env(env, cooldown_seconds=60)
    assert len(pool.proxies) == 2
    assert pool.cooldown_seconds == 60


def test_mask_hides_credentials():
    assert _mask("socks5://user:secret@1.2.3.4:1080") == "socks5://***@1.2.3.4:1080"
    assert _mask("socks5://1.2.3.4:1080") == "socks5://1.2.3.4:1080"
