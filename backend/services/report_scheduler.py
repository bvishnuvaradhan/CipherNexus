import asyncio
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from database.repository import fetch_recent, insert_document, update_document
from services.reporting import build_report_csv_content
from services.mailer import send_report_email


FREQUENCY_TO_DELTA = {
    "hourly": timedelta(hours=1),
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
}


async def materialize_scheduled_report(schedule: dict) -> dict:
    now = datetime.utcnow()
    lookback_hours = int(schedule.get("lookback_hours", 24) or 24)
    start_dt = now - timedelta(hours=max(1, lookback_hours))
    end_dt = now

    severity = schedule.get("severity")
    threat_types = schedule.get("threat_types") if isinstance(schedule.get("threat_types"), list) else []
    csv_content, row_count = await build_report_csv_content(
        start_dt=start_dt,
        end_dt=end_dt,
        severity=severity,
        threat_types=threat_types,
    )

    report_id = str(uuid4())
    filename = (
        f"scheduled-report-{schedule.get('id')}-"
        f"{start_dt.strftime('%Y%m%d_%H%M')}_to_{end_dt.strftime('%Y%m%d_%H%M')}.csv"
    )

    await insert_document(
        "scheduled_reports",
        {
            "id": report_id,
            "schedule_id": schedule.get("id"),
            "schedule_name": schedule.get("name"),
            "generated_at": now.isoformat(),
            "start_time": start_dt.isoformat(),
            "end_time": end_dt.isoformat(),
            "severity": severity,
            "threat_types": threat_types,
            "row_count": row_count,
            "filename": filename,
            "csv_content": csv_content,
        },
    )

    frequency = str(schedule.get("frequency", "daily") or "daily").lower()
    delta = FREQUENCY_TO_DELTA.get(frequency, timedelta(days=1))
    next_run_at = (now + delta).isoformat()

    await update_document(
        "report_schedules",
        {"id": schedule.get("id")},
        {
            "$set": {
                "last_run_at": now.isoformat(),
                "next_run_at": next_run_at,
                "updated_at": now.isoformat(),
            }
        },
    )

    return {
        "id": report_id,
        "schedule_id": schedule.get("id"),
        "schedule_name": schedule.get("name"),
        "generated_at": now.isoformat(),
        "start_time": start_dt.isoformat(),
        "end_time": end_dt.isoformat(),
        "severity": severity,
        "threat_types": threat_types,
        "row_count": row_count,
        "filename": filename,
    }


async def materialize_and_send_email_report(schedule: dict) -> dict:
    now = datetime.utcnow()
    lookback_hours = int(schedule.get("lookback_hours", 24) or 24)
    start_dt = now - timedelta(hours=max(1, lookback_hours))
    end_dt = now

    severity = schedule.get("severity")
    threat_types = schedule.get("threat_types") if isinstance(schedule.get("threat_types"), list) else []
    recipients = schedule.get("recipients") if isinstance(schedule.get("recipients"), list) else []
    csv_content, row_count = await build_report_csv_content(
        start_dt=start_dt,
        end_dt=end_dt,
        severity=severity,
        threat_types=threat_types,
    )

    report_id = str(uuid4())
    filename = (
        f"email-report-{schedule.get('id')}-"
        f"{start_dt.strftime('%Y%m%d_%H%M')}_to_{end_dt.strftime('%Y%m%d_%H%M')}.csv"
    )
    subject = f"CipherNexus Threat Report - {schedule.get('name', 'Scheduled Report')}"
    body = (
        f"Scheduled threat report generated at {now.isoformat()} UTC.\n"
        f"Window: {start_dt.isoformat()} to {end_dt.isoformat()}\n"
        f"Rows: {row_count}\n"
    )

    send_status = "sent"
    send_error = None
    try:
        await send_report_email(
            recipients=recipients,
            subject=subject,
            body=body,
            attachment_name=filename,
            attachment_content=csv_content,
        )
    except Exception as exc:
        send_status = "failed"
        send_error = str(exc)

    await insert_document(
        "email_report_runs",
        {
            "id": report_id,
            "schedule_id": schedule.get("id"),
            "schedule_name": schedule.get("name"),
            "sent_at": now.isoformat(),
            "start_time": start_dt.isoformat(),
            "end_time": end_dt.isoformat(),
            "severity": severity,
            "threat_types": threat_types,
            "row_count": row_count,
            "filename": filename,
            "recipients": recipients,
            "status": send_status,
            "error": send_error,
        },
    )

    interval_minutes = int(schedule.get("interval_minutes", 1440) or 1440)
    next_run_at = (now + timedelta(minutes=max(5, interval_minutes))).isoformat()
    await update_document(
        "email_report_schedules",
        {"id": schedule.get("id")},
        {
            "$set": {
                "last_run_at": now.isoformat(),
                "next_run_at": next_run_at,
                "last_error": send_error,
                "updated_at": now.isoformat(),
            }
        },
    )

    return {
        "id": report_id,
        "schedule_id": schedule.get("id"),
        "status": send_status,
        "error": send_error,
        "row_count": row_count,
    }


class ReportScheduler:
    def __init__(self, poll_seconds: int = 30):
        self._poll_seconds = max(10, poll_seconds)
        self._task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self):
        if self._task and not self._task.done():
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        print("[OK] Scheduled report worker started")

    async def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None

    async def _run_loop(self):
        while self._running:
            try:
                await self._tick()
            except Exception as exc:
                print(f"[WARN] Scheduled report tick failed: {exc}")
            await asyncio.sleep(self._poll_seconds)

    async def _tick(self):
        now_iso = datetime.utcnow().isoformat()
        due_schedules = await fetch_recent(
            "report_schedules",
            limit=200,
            query={"enabled": True, "next_run_at": {"$lte": now_iso}},
            sort_field="next_run_at",
        )
        for schedule in due_schedules:
            await materialize_scheduled_report(schedule)

        due_email_schedules = await fetch_recent(
            "email_report_schedules",
            limit=200,
            query={"enabled": True, "deleted": {"$ne": True}, "next_run_at": {"$lte": now_iso}},
            sort_field="next_run_at",
        )
        for schedule in due_email_schedules:
            await materialize_and_send_email_report(schedule)
