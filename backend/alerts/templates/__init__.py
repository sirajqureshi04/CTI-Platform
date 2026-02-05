"""Email alert templates for the CTI platform."""

# Explicit exports for easier importing
from backend.alerts.templates.alert import alert_template
from backend.alerts.templates.daily_brief import daily_brief_template

__all__ = [
    "alert_template",
    "daily_brief_template"
]       
