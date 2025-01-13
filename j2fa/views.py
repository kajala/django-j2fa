import logging
from datetime import timedelta, datetime
from typing import List, Tuple, Union
from django.conf import settings
from ipware.ip import get_client_ip  # type: ignore  # pytype: disable=import-error
from j2fa.errors import TwoFactorAuthError
from j2fa.forms import TwoFactorForm
from j2fa.models import TwoFactorSession
from j2fa.helpers import j2fa_make_code, j2fa_phone_filter, j2fa_send_sms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.http import HttpRequest
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils.timezone import now
from django.utils.translation import gettext as _
from django.views.generic import TemplateView
from django.core.mail import send_mail

logger = logging.getLogger(__name__)


class TwoFactorAuth(TemplateView):
    template_name = "j2fa/ask-code2.html"
    logout_view_name = "admin:logout"
    default_next_view_name = "admin:index"
    max_failed_attempts = 5
    max_failed_attempts_hours = 24
    code_expires_seconds = 300

    def get_user_email(self, user: User) -> str:
        """
        Allow user-specific customization of email address to receive the 2FA code.
        Return empty string if user is not supposed to get codes via email but email sending is enabled (J2FA_SEND_TO_EMAIL=True).
        :param user: User
        :return: Email address (if email should be used to send the code, empty otherwise)
        """
        return user.email

    def get_user_phone(self, user: User) -> str:
        """
        Returns User's phone number. By default uses User.profile.phone.
        :param user: User
        :return: str
        """
        if user.is_authenticated and hasattr(user, "profile") and hasattr(user.profile, "phone"):  # type: ignore
            return user.profile.phone  # type: ignore
        return ""

    def make_2fa_code(self) -> str:
        """
        Makes 2FA code.
        By default makes 4-6 digit integer code as str.
        :return: str
        """
        return j2fa_make_code()

    def get_context_data(self, **kw):
        request = self.request
        assert isinstance(request, HttpRequest)

        next_url = request.POST.get("next") if request.POST else None
        if not next_url:
            next_url = request.GET.get("next")
        if not next_url:
            next_url = request.META.get("HTTP_REFERER")
        if not next_url:
            next_url = reverse(self.default_next_view_name)

        cx = {
            "form": TwoFactorForm(data=request.POST or None),
            "next": next_url,
        }
        for k, v in kw.items():
            if v:
                cx[k] = v
        return cx

    def get(self, request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return redirect(self.logout_view_name)

        cx = self.get_context_data()
        try:
            ses = self.get_session(request)
            channel = request.GET.get("channel") or ""
            next_path = request.GET.get("next") or ""
            if channel:
                self.send_code(ses, channel=channel)
                return redirect(reverse("j2fa-obtain-auth") + f"?msg-resent={channel}&next={next_path}")
            msg_resent = request.GET.get("msg-resent") or ""
            if msg_resent:
                cx["info"] = _("msg.resent")
                cx["alt_channel"] = "I" if msg_resent == "M" else "M"
        except ValidationError as e:
            cx["error"] = " ".join(e.messages)

        return render(request, self.template_name, cx)

    def count_failed_attempts(self, user, since: datetime) -> int:
        return TwoFactorSession.objects.all().filter(user=user, created__gt=since, archived=False).count()

    def send_sms_code(self, phone: str, msg: str, channel: str = "") -> int:
        """
        Send SMS code.
        Args:
            phone: str
            msg: str
            channel: str

        Returns:
            HTTP response status, >300 on error.
        """
        res = j2fa_send_sms(phone, msg, channel=channel)
        return res.status_code

    def send_email_code(
        self, subject: str, body: str, sender: Union[str, Tuple[str, str]], recipient_list: List[Union[str, Tuple[str, str]]], fail_silently: bool = False
    ):
        """
        Emails the OTP code
        Args:
            subject:
            body:
            sender:
            recipient_list:
            fail_silently:

        Returns:
            None
        """
        send_mail(subject, body, sender, recipient_list, fail_silently=fail_silently)

    def send_code(self, ses: TwoFactorSession, channel: str = ""):
        logger.info("2FA: %s -> '%s' (%s) %s", ses.code, ses.phone, ses.user, channel)
        send_by_email = hasattr(settings, "J2FA_SEND_TO_EMAIL") and settings.J2FA_SEND_TO_EMAIL and ses.email
        if settings.SMS_TOKEN and ses.phone:
            status_code = self.send_sms_code(ses.phone, ses.code, channel=channel)
            if status_code >= 300 and hasattr(settings, "EMAIL_HOST") and settings.EMAIL_HOST:
                logger.warning("SMS sending failed to %s (%s), trying to send code by email", ses.phone, ses.user)
                send_by_email = settings.J2FA_FALLBACK_TO_EMAIL if hasattr(settings, "J2FA_FALLBACK_TO_EMAIL") else False
        if send_by_email:
            logger.info("2FA (email): %s -> %s (%s)", ses.code, ses.email, ses.user)
            subject = settings.SMS_SENDER_NAME + ": " + _("One time login code")
            body = _("j2fa.code.email.body").format(code=ses.code)
            sender = settings.DEFAULT_FROM_EMAIL
            recipient = ses.email
            self.send_email_code(subject, body, sender, [recipient], fail_silently=False)

    def get_session(self, request: HttpRequest, force: bool = False) -> TwoFactorSession:
        user, ip, user_agent, phone, email = self.get_session_const(request)
        ses_id = request.session.get("j2fa_session")
        ses = TwoFactorSession.objects.filter(id=ses_id).first() if ses_id else None
        assert ses is None or isinstance(ses, TwoFactorSession)
        time_now = now()
        if not ses or not ses.is_valid(user, ip, user_agent) or force or time_now - ses.created > timedelta(seconds=self.code_expires_seconds):
            since = time_now - timedelta(hours=self.max_failed_attempts_hours)
            if self.count_failed_attempts(user, since) > self.max_failed_attempts:
                raise TwoFactorAuthError(_("too.many.failed.attempts"))

            ses = TwoFactorSession.objects.create(
                user=user,
                ip=ip,
                user_agent=user_agent[:512],
                phone=phone,
                email=email,
                code=self.make_2fa_code(),
            )
            assert isinstance(ses, TwoFactorSession)
            self.send_code(ses)
            request.session["j2fa_session"] = ses.id
        return ses

    def get_session_const(self, request: HttpRequest):
        user = request.user
        ip = get_client_ip(request)[0]
        if ip is None and settings.DEBUG:
            ip = "127.0.0.1"
        user_agent = str(request.META["HTTP_USER_AGENT"])[:512]
        phone = j2fa_phone_filter(self.get_user_phone(user))  # type: ignore
        email = self.get_user_email(user)  # type: ignore
        if not phone:
            raise TwoFactorAuthError(_("your.phone.number.missing.from.system"))
        return user, ip, user_agent, phone, email

    def post(self, request, *args, **kwargs):  # pylint: disable=unused-argument
        cx = self.get_context_data()
        form = cx["form"]
        assert isinstance(form, TwoFactorForm)

        if form.is_valid():
            try:
                ses = self.get_session(request)
                assert isinstance(ses, TwoFactorSession)
                code = form.cleaned_data["code"]
                user, ip, user_agent, phone, email = self.get_session_const(request)
                logger.info("2FA: Post %s %s %s %s %s vs %s", user, ip, user_agent, phone, email, ses.code)
                if ses.code != code:
                    code_expire_time_s = self.code_expires_seconds
                    if code_expire_time_s > 0 and code:
                        time_now = now()
                        old = time_now - timedelta(seconds=code_expire_time_s)
                        recent = (
                            TwoFactorSession.objects.filter(created__gte=old, user=user, ip=ip, user_agent=user_agent[:512], code=code, archived=False)
                            .order_by("-id")
                            .first()
                        )
                        if recent is not None:
                            assert isinstance(recent, TwoFactorSession)
                            logger.info("2FA: Passing %s as code %s matches %s (age %s)", user, code, recent, time_now - recent.created)
                        else:
                            self.get_session(request, force=True)
                            raise TwoFactorAuthError(_("Invalid code, sending a new one."))
                    else:
                        self.get_session(request, force=True)
                        raise TwoFactorAuthError(_("Invalid code, sending a new one."))
                logger.info("2FA: Pass %s / %s", user, ses)
                ses.activate()

                return redirect(cx.get("next"))
            except TwoFactorAuthError as exc:
                form.add_error(None, exc)
            except Exception as exc:
                form.add_error(None, exc)

        return render(request, self.template_name, cx)
