import asyncio
from typing import Callable, Dict, List

class EventBus:
    def __init__(self):
        self._handlers: Dict[str, List[Callable]] = {}
    
    def subscribe(self, event_type: str, handler: Callable):
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
    
    async def publish(self, event_type: str, data):
        if event_type not in self._handlers:
            return
        for handler in self._handlers[event_type]:
            result = handler(data)
            if asyncio.iscoroutine(result):
                await result