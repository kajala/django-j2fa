import logging
from j2fa.models import TwoFactorSession
from django.conf import settings
from ipware.ip import get_client_ip  # type: ignore  # pytype: disable=import-error
from django.http import HttpRequest

logger = logging.getLogger(__name__)


def auth_2fa(request: HttpRequest, user, reason: str = ""):
    """
    By-pass 2FA requirement for this user session.
    Call auth.login() before this function if the user is not logged in yet.
    :param request:
    :param user:
    :param reason: Optional reason for by-passing 2FA, e.g. "bank ID". Just stored in log.
    :return:
    """
    ip = get_client_ip(request)[0]
    if ip is None and settings.DEBUG:
        ip = "127.0.0.1"
    user_agent = request.META["HTTP_USER_AGENT"]
    ses = TwoFactorSession.objects.create(
        user=user,
        ip=ip,
        user_agent=user_agent[:512],
        phone="",
        email=user.email,
        code="",
    )
    assert isinstance(ses, TwoFactorSession)
    request.session["j2fa_session"] = ses.id
    ses.activate()
    logger.info("User %s (IP %s) 2FA requirement by-passed (reason: %s)", user, ip, reason)
