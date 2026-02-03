import json
import logging
import os
import time
from datetime import datetime
from app.models import Task, EmailEvidence
from app.extensions import db
from app.email_parser import parse_email
from app.correlation_engine import correlate_evidence

logger = logging.getLogger(__name__)

def add_task(task_type, payload):
    """
    Adds a new task to the queue.
    """
    try:
        task = Task(
            task_type=task_type,
            payload=json.dumps(payload),
            status='pending'
        )
        db.session.add(task)
        db.session.commit()
        logger.info(f"Task {task.id} ({task_type}) added to queue.")
        return task.id
    except Exception as e:
        logger.error(f"Error adding task: {e}")
        return None

def process_email_task(payload):
    evidence_id = payload.get('evidence_id')
    filepath = payload.get('filepath')

    if not evidence_id or not filepath:
        raise ValueError("Missing evidence_id or filepath")

    evidence = EmailEvidence.query.get(evidence_id)
    if not evidence:
        raise ValueError(f"Evidence {evidence_id} not found")

    try:
        # Parse Email
        logger.info(f"Parsing email file: {filepath}")
        with open(filepath, 'rb') as f:
            parsed_data = parse_email(f, evidence.filename)

        # Update Evidence Record
        evidence.headers = json.dumps(parsed_data['headers'])
        evidence.body = parsed_data['body'] # Text/HTML
        evidence.extracted_indicators = json.dumps(parsed_data['indicators'])

        # Determine if there's an analysis report (e.g. from headers) or placeholder
        # For now, we can perhaps run VT checks here and store as analysis_report?
        # User asked to "Enrich... check URL/IP/Domain Reputation".

        from app.utils import check_vt_reputation

        analysis = {
            'vt_stats': {}
        }

        indicators = parsed_data['indicators']
        for ip in indicators.get('ips', [])[:5]: # Limit to first 5 to avoid quota hits
            stats = check_vt_reputation(ip, 'ip')
            if stats:
                analysis['vt_stats'][ip] = stats

        for domain in indicators.get('domains', [])[:5]:
            stats = check_vt_reputation(domain, 'domain')
            if stats:
                analysis['vt_stats'][domain] = stats

        # URLs - VT API for URLs requires submission usually.
        # check_vt_reputation handles lookup.
        for url in indicators.get('urls', [])[:5]:
            stats = check_vt_reputation(url, 'url')
            if stats:
                analysis['vt_stats'][url] = stats

        evidence.analysis_report = json.dumps(analysis)
        db.session.commit()

        # Correlate
        logger.info("Running correlation...")
        correlate_evidence(evidence.id)

        # Cleanup
        if os.path.exists(filepath):
            os.remove(filepath)

        return "Processed and Correlated"

    except Exception as e:
        logger.error(f"Failed to process email: {e}")

        # Try to save error to evidence record
        try:
            error_report = {'error': str(e), 'failed_at': datetime.utcnow().isoformat()}
            # Load existing if possible
            if evidence.analysis_report:
                try:
                    existing = json.loads(evidence.analysis_report)
                    existing.update(error_report)
                    error_report = existing
                except:
                    pass

            evidence.analysis_report = json.dumps(error_report)
            if not evidence.body:
                evidence.body = f"Processing Failed: {str(e)}"
            db.session.commit()
        except Exception as db_e:
            logger.error(f"Failed to save error state: {db_e}")

        # If failed, maybe keep file for retry? Or delete?
        # For now, we assume failure requires manual intervention or re-upload.
        raise e

def process_next_task():
    """
    Picks the next pending task and executes it.
    Returns True if a task was processed, False otherwise.
    """
    # Lock/Select
    # Use with_for_update(skip_locked=True) to handle distributed workers.
    # skip_locked=True allows other workers to skip rows locked by this transaction, preventing bottlenecks.
    # Note: SQLite will ignore this clause or handle it gracefully, making it safe for dev/test.

    task = Task.query.filter_by(status='pending').order_by(Task.created_at.asc()).with_for_update(skip_locked=True).first()

    if not task:
        return False

    logger.info(f"Processing Task {task.id}: {task.task_type}")
    task.status = 'processing'
    db.session.commit()

    try:
        payload = json.loads(task.payload)
        result = None

        if task.task_type == 'process_email':
            result = process_email_task(payload)
        elif task.task_type == 'refresh_correlations':
             from app.correlation_engine import refresh_correlations
             count = refresh_correlations()
             result = f"Correlations refreshed. {count} new matches."
        else:
            raise ValueError(f"Unknown task type: {task.task_type}")

        task.status = 'completed'
        task.result = str(result)
        db.session.commit()
        return True

    except Exception as e:
        logger.error(f"Task {task.id} failed: {e}")
        task.status = 'failed'
        task.result = str(e)
        db.session.commit()
        return True # Task was processed (even if failed)
