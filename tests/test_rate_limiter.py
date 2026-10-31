"""
Unit tests for the WAF Sliding Window Rate Limiter.
"""
import time
from waf.rate_limiter import SlidingWindowRateLimiter

def test_rate_limiter_allows_under_limit():
    limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=2)
    client_ip = "192.168.1.10"

    for _ in range(5):
        allowed, retry_after = limiter.is_allowed(client_ip)
        assert allowed is True
        assert retry_after == 0

def test_rate_limiter_blocks_over_limit():
    limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=2)
    client_ip = "10.0.0.99"

    for _ in range(3):
        allowed, _ = limiter.is_allowed(client_ip)
        assert allowed is True

    # 4th request must be blocked
    allowed, retry_after = limiter.is_allowed(client_ip)
    assert allowed is False
    assert retry_after > 0

def test_rate_limiter_resets_after_window():
    limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=1)
    client_ip = "127.0.0.1"

    assert limiter.is_allowed(client_ip)[0] is True
    assert limiter.is_allowed(client_ip)[0] is True
    assert limiter.is_allowed(client_ip)[0] is False

    time.sleep(1.1)
    # Should be allowed again after window expires
    assert limiter.is_allowed(client_ip)[0] is True
