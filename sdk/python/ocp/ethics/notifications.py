"""
Proactive Notification subsystem — 30-day SLA for affected individuals.
Ref: OCP Ethics Bible v2.1 §30
"""
from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta


@dataclass
class Notification:
    """A notification to an affected individual."""
    notification_id: str = ""
    affected_individual: str = ""
    decision_type: str = ""
    data_categories: list[str] = field(default_factory=list)
    agents_involved: list[str] = field(default_factory=list)
    explanation_url: str = ""
    contest_url: str = ""
    language: str = "en"
    created_at: str = ""
    due_at: str = ""
    sent_at: str | None = None
    channel: str = ""  # email, postal, in_app

    def __post_init__(self):
        if not self.notification_id:
            self.notification_id = f"ntf-{uuid.uuid4()}"
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.due_at:
            due = datetime.now(timezone.utc) + timedelta(days=30)
            self.due_at = due.isoformat()

    def is_overdue(self) -> bool:
        if self.sent_at:
            return False
        return datetime.now(timezone.utc).isoformat() > self.due_at


class NotificationManager:
    """Manages proactive notification obligations."""

    def __init__(self, sender=None):
        self.sender = sender
        self._pending: dict[str, Notification] = {}
        self._sent: dict[str, Notification] = {}

    def create(self, affected_individual: str, decision_type: str,
               agents_involved: list[str], **kwargs) -> Notification:
        notification = Notification(
            affected_individual=affected_individual,
            decision_type=decision_type,
            agents_involved=agents_involved,
            **kwargs
        )
        self._pending[notification.notification_id] = notification
        return notification

    async def send(self, notification_id: str) -> bool:
        notification = self._pending.get(notification_id)
        if not notification:
            return False
        if self.sender:
            await self.sender(notification)
        notification.sent_at = datetime.now(timezone.utc).isoformat()
        self._sent[notification_id] = notification
        del self._pending[notification_id]
        return True

    def get_overdue(self) -> list[Notification]:
        return [n for n in self._pending.values() if n.is_overdue()]

    def get_pending(self) -> list[Notification]:
        return list(self._pending.values())
