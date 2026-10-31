"""
Thread-safe Sliding Window Rate Limiter for the Mini WAF.
Protects upstream applications from volumetric brute-force and rapid fuzzing.
"""
from collections import defaultdict
import threading
import time

class SlidingWindowRateLimiter:
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
        self.lock = threading.Lock()

    def is_allowed(self, client_ip: str) -> tuple[bool, int]:
        """
        Check if request from client_ip is allowed under rate limit threshold.

        Returns:
            tuple: (allowed: bool, retry_after_seconds: int)
        """
        now = time.time()
        cutoff = now - self.window_seconds

        with self.lock:
            # Filter out timestamps older than the sliding window
            timestamps = [ts for ts in self.requests[client_ip] if ts > cutoff]
            self.requests[client_ip] = timestamps

            if len(timestamps) >= self.max_requests:
                # Calculate time until the oldest request in the current window expires
                oldest = timestamps[0]
                retry_after = max(1, int(oldest + self.window_seconds - now))
                return False, retry_after

            self.requests[client_ip].append(now)
            return True, 0

    def reset(self):
        """Clear all stored rate limit history."""
        with self.lock:
            self.requests.clear()
