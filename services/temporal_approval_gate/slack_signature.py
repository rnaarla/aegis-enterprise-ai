"""Slack Block Kit Interactive Webhook `v0` HMAC-SHA256 Signature Verifier."""

from __future__ import annotations

import hashlib
import hmac
import time

SLACK_REPLAY_WINDOW_SECONDS = 300


class SlackWebhookVerificationError(Exception):
    """Raised when `X-Slack-Signature` or 5-minute replay timestamp validation fails."""


def sign_slack_webhook_payload(
    *,
    signing_secret: str,
    timestamp: int,
    raw_body: bytes,
) -> str:
    """Compute Slack `v0=<hex>` HMAC-SHA256 signature over `v0:{timestamp}:{raw_body}`."""
    basestring = f"v0:{timestamp}:".encode() + raw_body
    digest = hmac.new(signing_secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()
    return f"v0={digest}"


def verify_slack_webhook_signature(
    *,
    signing_secret: str,
    timestamp_header: str,
    signature_header: str,
    raw_body: bytes,
    now_epoch: int | None = None,
) -> None:
    """Verify Slack Block Kit interactive webhook HMAC-SHA256 in constant time."""
    try:
        ts = int(timestamp_header)
    except ValueError as exc:
        raise SlackWebhookVerificationError("Invalid X-Slack-Request-Timestamp") from exc

    now = now_epoch if now_epoch is not None else int(time.time())
    if abs(now - ts) > SLACK_REPLAY_WINDOW_SECONDS:
        raise SlackWebhookVerificationError("Slack webhook timestamp outside 300s replay window")

    expected_sig = sign_slack_webhook_payload(
        signing_secret=signing_secret,
        timestamp=ts,
        raw_body=raw_body,
    )
    if not hmac.compare_digest(expected_sig, signature_header):
        raise SlackWebhookVerificationError("Slack HMAC-SHA256 signature mismatch")
