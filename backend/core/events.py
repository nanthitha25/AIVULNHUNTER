from typing import List, Dict, Any, Callable, Awaitable
from collections import defaultdict
import asyncio
import logging
from uuid import UUID, uuid4
from datetime import datetime
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class Event(BaseModel):
    """Base event model."""
    id: str = str(uuid4())
    type: str
    timestamp: datetime = datetime.utcnow()
    payload: Dict[str, Any] = {}

class EventBus:
    """
    Simple in-memory event bus for decoupled agent communication.
    """
    def __init__(self):
        self._subscribers: Dict[str, List[Callable[[Event], Awaitable[None]]]] = defaultdict(list)

    def subscribe(self, event_type: str, handler: Callable[[Event], Awaitable[None]]):
        """Subscribe a handler to an event type."""
        self._subscribers[event_type].append(handler)
        logger.debug(f"Subscribed handler to {event_type}")

    async def publish(self, event: Event):
        """Publish an event to all subscribers."""
        if event.type in self._subscribers:
            handlers = self._subscribers[event.type]
            # Execute handlers concurrently
            await asyncio.gather(*(handler(event) for handler in handlers), return_exceptions=True)
            logger.debug(f"Published event {event.type} to {len(handlers)} handlers")

# Global event bus instance
event_bus = EventBus()
