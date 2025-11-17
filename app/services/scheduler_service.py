"""
APScheduler service for automated backups
"""
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from flask import current_app


def run_scheduled_backup(routine_id, app):
    """Executes a scheduled backup in background"""
    with app.app_context():
        try:
            from app.models import BackupRoutine
            from app.services.backup_service import execute_backup

            routine = BackupRoutine.query.get(routine_id)
            if routine and routine.enabled:
                print(f"[SCHEDULER] Executing scheduled backup: {routine.name}")
                execute_backup(routine)
            else:
                print(f"[SCHEDULER] Routine {routine_id} disabled or not found")
        except Exception as e:
            print(f"[SCHEDULER] Error executing scheduled backup {routine_id}: {str(e)}")


def schedule_routine(scheduler, routine, app):
    """Adds a routine to the scheduler"""
    if not routine.enabled or routine.schedule_type == 'manual':
        return

    if not routine.schedule_time:
        return

    try:
        # Parse time (HH:MM format)
        hour, minute = map(int, routine.schedule_time.split(':'))

        # Create trigger based on schedule type
        if routine.schedule_type == 'daily':
            trigger = CronTrigger(hour=hour, minute=minute)
            scheduler.add_job(
                func=run_scheduled_backup,
                trigger=trigger,
                args=[routine.id, app],
                id=f'routine_{routine.id}',
                replace_existing=True,
                name=f'Backup: {routine.name}'
            )
            print(f"[SCHEDULER] Scheduled daily: {routine.name} at {routine.schedule_time}")

        elif routine.schedule_type == 'weekly':
            # Execute every Monday (day_of_week=0)
            trigger = CronTrigger(day_of_week=0, hour=hour, minute=minute)
            scheduler.add_job(
                func=run_scheduled_backup,
                trigger=trigger,
                args=[routine.id, app],
                id=f'routine_{routine.id}',
                replace_existing=True,
                name=f'Backup: {routine.name}'
            )
            print(f"[SCHEDULER] Scheduled weekly: {routine.name} at {routine.schedule_time}")

        elif routine.schedule_type == 'monthly':
            # Execute on day 1 of each month
            trigger = CronTrigger(day=1, hour=hour, minute=minute)
            scheduler.add_job(
                func=run_scheduled_backup,
                trigger=trigger,
                args=[routine.id, app],
                id=f'routine_{routine.id}',
                replace_existing=True,
                name=f'Backup: {routine.name}'
            )
            print(f"[SCHEDULER] Scheduled monthly: {routine.name} at {routine.schedule_time}")

    except Exception as e:
        print(f"[SCHEDULER] Error scheduling routine {routine.name}: {str(e)}")


def init_scheduler(app):
    """Initializes the scheduler and loads all routines"""
    from app.models import BackupRoutine
    from app.extensions import db

    scheduler = BackgroundScheduler()
    scheduler.start()

    routines = []
    with app.app_context():
        # Check if tables exist before attempting to query
        try:
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            if 'backup_routine' in inspector.get_table_names():
                routines = BackupRoutine.query.filter_by(enabled=True).all()
                for routine in routines:
                    schedule_routine(scheduler, routine, app)
            else:
                print("[SCHEDULER] Tables not yet created, will be initialized after migration")
        except Exception as e:
            print(f"[SCHEDULER] Warning: Could not load routines: {str(e)}")

    print(f"[SCHEDULER] Initialized with {len(routines)} active routines")

    # Ensure scheduler is shut down on exit
    atexit.register(lambda: scheduler.shutdown())

    return scheduler


def update_routine_schedule(routine, scheduler, app):
    """Updates the schedule of a specific routine"""
    if scheduler:
        try:
            # Remove old job if it exists
            try:
                scheduler.remove_job(f'routine_{routine.id}')
            except:
                pass

            # Add new schedule
            schedule_routine(scheduler, routine, app)
        except Exception as e:
            print(f"[SCHEDULER] Error updating schedule: {str(e)}")
