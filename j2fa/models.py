#pylint: disable=logging-format-interpolation
import logging
from datetime import timedelta
from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.db.models import Q
from django.utils.timezone import now
from j2fa.helpers import j2fa_make_code, j2fa_send_sms


logger = logging.getLogger(__name__)

A2FA_SESSION_EXPIRES_MINUTES = 60*24
A2FA_SESSION_CLEANUP_DAYS = 7


class TwoFactorSessionManager(models.Manager):
    def count_failed_attempts(self, user, ip, since):
        return self.filter(Q(ip=ip) | Q(user=user)).filter(created__gt=since, archived=False).count()

    def archive_old_sessions(self, user: User, current):
        self.filter(user=user).exclude(id=current.id).update(archived=True, active=False)
        current.active = True
        current.archived = False
        current.save()

    def clean_up_old_sessions(self):
        old = now() - timedelta(days=A2FA_SESSION_CLEANUP_DAYS)
        self.filter(created__lt=old).delete()


class TwoFactorSession(models.Model):
    objects = TwoFactorSessionManager()
    created = models.DateTimeField(default=now, db_index=True, blank=True)
    user = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE)
    user_agent = models.CharField(max_length=512)
    ip = models.GenericIPAddressField(db_index=True)
    phone = models.CharField(max_length=32, db_index=True)
    code = models.CharField(max_length=8, default=j2fa_make_code, blank=True)
    active = models.BooleanField(default=False, db_index=True, blank=True)
    archived = models.BooleanField(default=False, db_index=True, blank=True)

    def __str__(self):
        return '[{}]'.format(self.id)

    def is_valid(self, user: User, ip: str, user_agent: str) -> bool:
        if now() - self.created > timedelta(minutes=A2FA_SESSION_EXPIRES_MINUTES):
            return False
        return self.user == user and self.ip == ip and self.user_agent == user_agent

    def send_code(self):
        logger.info('2FA_SEND_CODE: {} / {} / {}'.format(self.user, self.phone, self.code))
        if settings.SMS_TOKEN:
            j2fa_send_sms(self.phone, self.code)
