from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from monitoring.models import APILog, UserActivity
from django.conf import settings


class Command(BaseCommand):
    help = 'Clean old logs from the database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Delete logs older than specified days (default: 30)'
        )

    def handle(self, *args, **options):
        days = options['days']
        cutoff_date = timezone.now() - timedelta(days=days)

        # Delete old API logs
        old_api_logs_count = APILog.objects.filter(timestamp__lt=cutoff_date).count()
        APILog.objects.filter(timestamp__lt=cutoff_date).delete()

        # Delete old user activities
        old_user_activities_count = UserActivity.objects.filter(timestamp__lt=cutoff_date).count()
        UserActivity.objects.filter(timestamp__lt=cutoff_date).delete()

        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully cleaned logs older than {days} days:\n'
                f'- Deleted {old_api_logs_count} API logs\n'
                f'- Deleted {old_user_activities_count} user activity logs'
            )
        )