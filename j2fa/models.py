import logging
from django.contrib.auth.models import User
from django.db import models
from django.conf import settings
from django.utils.timezone import now
from j2fa.helpers import j2fa_make_code

logger = logging.getLogger(__name__)


class TwoFactorSession(models.Model):
    created = models.DateTimeField(default=now, db_index=True, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="+", on_delete=models.CASCADE)
    user_agent = models.CharField(max_length=512)
    ip = models.GenericIPAddressField(db_index=True)
    phone = models.CharField(max_length=32, db_index=True)
    email = models.EmailField(blank=True, default="")
    code = models.CharField(max_length=8, default=j2fa_make_code, blank=True)
    active = models.BooleanField(default=False, db_index=True, blank=True)
    archived = models.BooleanField(default=False, db_index=True, blank=True)

    def __str__(self):
        return "[{}]".format(self.id)

    @staticmethod
    def check_ip(ip_a: str, ip_b: str) -> bool:
        """
        Only compares first 2 parts of the IP address to avoid issues with frequently changing IPs.
        :param ip_a:
        :param ip_b:
        :return: bool
        """
        return ip_a.split(".")[:2] == ip_b.split(".")[:2]

    def activate(self):
        self.active = True
        self.archived = False
        self.save()
        TwoFactorSession.objects.all().filter(user=self.user).exclude(id=self.id).update(archived=True, active=False)

    def is_valid(self, user: User, ip: str, user_agent: str) -> bool:
        return self.user == user and self.check_ip(self.ip, ip) and self.user_agent[:512] == user_agent[:512]
