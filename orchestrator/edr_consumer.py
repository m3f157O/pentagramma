"""Consumer for the EDR agent's Server-Sent Events (SSE) stream.

The EDR agent exposes `/api/stream` on 127.0.0.1:8443 inside the guest.
In the sandbox, the orchestrator connects to the guest IP and reads events
as JSON payloads over SSE.
"""

import json
import time
from typing import Callable, Dict, List, Optional

import requests


class EdrEventConsumer:
    def __init__(
        self,
        host: str,
        port: int = 8443,
        path: str = "/api/stream",
        timeout: float = 5.0,
    ):
        self.base_url = f"http://{host}:{port}{path}"
        self.timeout = timeout
        self.events: List[Dict[str, any]] = []
        self._running = False

    def connect(self, max_retries: int = 30, retry_delay: float = 2.0) -> bool:
        """Wait for the EDR dashboard to become reachable."""
        for attempt in range(max_retries):
            try:
                resp = requests.get(self.base_url, stream=True, timeout=self.timeout)
                if resp.status_code == 200:
                    return True
            except requests.RequestException:
                pass
            time.sleep(retry_delay)
        return False

    def collect(
        self,
        duration_seconds: float,
        callback: Optional[Callable[[Dict[str, any]], None]] = None,
    ) -> List[Dict[str, any]]:
        """Open SSE stream and collect events for a fixed duration."""
        self.events = []
        self._running = True
        start = time.time()

        try:
            with requests.get(self.base_url, stream=True, timeout=self.timeout + duration_seconds) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if not self._running:
                        break
                    if time.time() - start >= duration_seconds:
                        break
                    if not line:
                        continue
                    text = line.decode("utf-8", errors="ignore")
                    # SSE lines look like: data: {"EventType": ...}
                    if text.startswith("data:"):
                        payload = text[5:].strip()
                        if payload:
                            try:
                                event = json.loads(payload)
                                self.events.append(event)
                                if callback:
                                    callback(event)
                            except json.JSONDecodeError:
                                continue
        except requests.RequestException as exc:
            # Log and return what we got
            print(f"[edr_consumer] SSE connection error: {exc}")

        return self.events

    def stop(self) -> None:
        self._running = False
