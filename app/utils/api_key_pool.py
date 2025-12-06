import asyncio
from collections import deque
from typing import Any, Dict, List


class APIKeyPool:
    """Manages API keys for parallel requests with rate limiting."""

    def __init__(self, clients: List[Any], max_concurrent_per_key: int = 2):
        self.clients = clients
        self.max_concurrent_per_key = max_concurrent_per_key

        # Semaphore for each key to limit concurrent requests
        self.key_semaphores = [
            asyncio.Semaphore(max_concurrent_per_key) for _ in range(len(clients))
        ]

        # Queue of available key indices
        self.available_keys = deque(range(len(clients)))
        self.key_lock = asyncio.Lock()

        # Track key usage stats
        self.key_stats = {
            i: {"requests": 0, "failures": 0, "active": 0} for i in range(len(clients))
        }

    async def acquire_key(self) -> tuple[int, Any]:
        """Acquire an available API key for use."""
        while True:
            async with self.key_lock:
                if self.available_keys:
                    key_idx = self.available_keys.popleft()
                    self.key_stats[key_idx]["active"] += 1
                    return key_idx, self.clients[key_idx]

            # No keys available, wait a bit
            await asyncio.sleep(0.1)

    async def release_key(self, key_idx: int, success: bool = True):
        """Release a key back to the pool."""
        async with self.key_lock:
            self.available_keys.append(key_idx)
            self.key_stats[key_idx]["requests"] += 1
            self.key_stats[key_idx]["active"] -= 1
            if not success:
                self.key_stats[key_idx]["failures"] += 1

    def get_stats(self) -> Dict:
        """Get usage statistics for all keys."""
        return {
            "total_keys": len(self.clients),
            "key_stats": self.key_stats,
            "available_keys": len(self.available_keys),
        }
