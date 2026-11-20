"""Human-readable dates; API and database values remain ISO for interoperability."""
import re
from datetime import date, datetime, timezone, timedelta

LOCAL_TZ = timezone(timedelta(hours=7))


def display_date(value):
    if not value:
        return ''
    if isinstance(value, (date, datetime)):
        return value.strftime('%d/%m/%Y')
    text = str(value)
    if re.fullmatch(r'\d{4}-\d{2}-\d{2}', text):
        try:
            return date.fromisoformat(text).strftime('%d/%m/%Y')
        except ValueError:
            pass
    return text


def display_time(value):
    if not value:
        return ''
    if isinstance(value, datetime):
        if value.tzinfo:
            value = value.astimezone(LOCAL_TZ)
        return value.strftime('%d/%m/%Y %H:%M:%S')
    return display_date(value)


def display_changes(value, date_field=False):
    if isinstance(value, dict):
        return {k: display_changes(v, date_field or k.endswith('_date')) for k,v in value.items()}
    if isinstance(value, list):
        return [display_changes(v, date_field) for v in value]
    return display_date(value) if date_field else value
