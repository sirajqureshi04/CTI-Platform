"""
Email alert service.

Sends email alerts for high-risk IOCs and threat intelligence.
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)


class EmailService:
    """
    Email alert service.
    
    Sends email notifications for threat intelligence alerts.
    """
    
    def __init__(self, cache_dir: Path = None):
        """
        Initialize email service.
        
        Args:
            cache_dir: Directory for alert cache
        """
        self.smtp_host = os.getenv("SMTP_HOST", "localhost")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.from_email = os.getenv("ALERT_FROM_EMAIL", "cti-platform@example.com")
        self.to_emails = os.getenv("ALERT_TO_EMAILS", "").split(",") if os.getenv("ALERT_TO_EMAILS") else []
        
        # Setup alert cache directories
        if cache_dir is None:
            cache_dir = Path(__file__).parent.parent / "cache" / "alerts"
        self.cache_dir = Path(cache_dir)
        self.pending_dir = self.cache_dir / "pending"
        self.sent_dir = self.cache_dir / "sent"
        self.failed_dir = self.cache_dir / "failed"
        
        # Create cache directories
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        self.sent_dir.mkdir(parents=True, exist_ok=True)
        self.failed_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("Initialized email service")
    
    def send_alert(
        self,
        subject: str,
        body: str,
        recipients: Optional[List[str]] = None,
        html: bool = False
    ) -> bool:
        """
        Send email alert.
        
        Args:
            subject: Email subject
            body: Email body
            recipients: List of recipient emails (uses default if None)
            html: Whether body is HTML
            
        Returns:
            True if sent successfully
        """
        if not recipients:
            recipients = self.to_emails
        
        if not recipients:
            logger.warning("No email recipients configured")
            return False
        
        # Save to pending cache
        alert_id = self._save_to_pending(subject, body, recipients, html)
        
        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = self.from_email
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = subject
            
            if html:
                msg.attach(MIMEText(body, "html"))
            else:
                msg.attach(MIMEText(body, "plain"))
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_user and self.smtp_password:
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            # Move to sent cache
            self._move_to_sent(alert_id)
            logger.info(f"Sent alert email to {recipients}")
            return True
            
        except Exception as e:
            # Move to failed cache
            self._move_to_failed(alert_id, str(e))
            logger.error(f"Failed to send alert email: {e}")
            return False
    
    def _save_to_pending(self, subject: str, body: str, recipients: List[str], html: bool) -> str:
        """Save alert to pending cache."""
        import json
        from datetime import datetime
        import hashlib
        
        alert_data = {
            "subject": subject,
            "body": body,
            "recipients": recipients,
            "html": html,
            "created_at": datetime.now().isoformat()
        }
        
        alert_id = hashlib.sha256(f"{subject}{body}{datetime.now()}".encode()).hexdigest()[:16]
        alert_file = self.pending_dir / f"{alert_id}.json"
        
        with open(alert_file, "w", encoding="utf-8") as f:
            json.dump(alert_data, f, indent=2)
        
        return alert_id
    
    def _move_to_sent(self, alert_id: str) -> None:
        """Move alert from pending to sent."""
        pending_file = self.pending_dir / f"{alert_id}.json"
        if pending_file.exists():
            sent_file = self.sent_dir / f"{alert_id}.json"
            pending_file.rename(sent_file)
    
    def _move_to_failed(self, alert_id: str, error: str) -> None:
        """Move alert from pending to failed."""
        pending_file = self.pending_dir / f"{alert_id}.json"
        if pending_file.exists():
            import json
            failed_file = self.failed_dir / f"{alert_id}.json"
            
            # Load and update with error
            with open(pending_file, "r", encoding="utf-8") as f:
                alert_data = json.load(f)
            alert_data["error"] = error
            alert_data["failed_at"] = self._get_timestamp()
            
            with open(failed_file, "w", encoding="utf-8") as f:
                json.dump(alert_data, f, indent=2)
            
            pending_file.unlink()
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def send_ioc_alert(self, ioc: Dict[str, Any]) -> bool:
        """
        Send alert for a high-risk IOC.
        
        Args:
            ioc: IOC dictionary
            
        Returns:
            True if sent successfully
        """
        subject = f"CTI Alert: High-Risk IOC Detected - {ioc.get('ioc_type', 'unknown')}"
        
        body = f"""
CTI Platform Alert

High-Risk IOC Detected:

Type: {ioc.get('ioc_type', 'unknown')}
Value: {ioc.get('ioc_value', 'unknown')}
Risk Level: {ioc.get('risk_level', 'unknown')}
Risk Score: {ioc.get('risk_score', 0)}
Source: {ioc.get('source', 'unknown')}

First Seen: {ioc.get('first_seen', 'unknown')}
Last Seen: {ioc.get('last_seen', 'unknown')}

Metadata:
{ioc.get('metadata', {})}

Please review and take appropriate action.
        """
        
        return self.send_alert(subject, body.strip())
    
    def send_daily_brief(self, statistics: Dict[str, Any]) -> bool:
        """
        Send daily threat intelligence brief.
        
        Args:
            statistics: Platform statistics dictionary
            
        Returns:
            True if sent successfully
        """
        subject = "CTI Platform Daily Threat Intelligence Brief"
        
        body = f"""
CTI Platform Daily Brief

Statistics:
- Total IOCs: {statistics.get('total_iocs', 0)}
- High-Risk IOCs: {statistics.get('high_risk_count', 0)}
- Feeds Processed: {statistics.get('feeds_processed', 0)}

IOCs by Type:
{statistics.get('iocs_by_type', {})}

IOCs by Risk Level:
{statistics.get('iocs_by_risk', {})}
        """
        
        return self.send_alert(subject, body.strip())

