#pylint: disable=logging-format-interpolation
import logging
from datetime import timedelta
from django.conf import settings
from ipware.ip import get_real_ip
from j2fa.errors import TwoFactorAuthError
from j2fa.forms import TwoFactorForm
from j2fa.models import TwoFactorSession
from j2fa.helpers import j2fa_make_code, j2fa_phone_filter
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.http import HttpRequest
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils.timezone import now
from django.utils.translation import gettext as _
from django.views.generic import TemplateView


DEFAULT_MAX_FAILED_ATTEMPTS_24H = 5  # can be overriden with settings.MAX_FAILED_ATTEMPTS_24H

logger = logging.getLogger(__name__)


class TwoFactorAuth(TemplateView):
    template_name = 'j2fa/ask-code2.html'
    logout_view_name = 'admin:logout'
    default_next_view_name = 'admin:index'

    def get_user_phone(self, user: User):
        assert user
        assert user.profile
        return user.profile.phone

    def get_context_data(self, **kw):
        request = self.request
        assert isinstance(request, HttpRequest)

        next_url = request.POST.get('next') if request.POST else None
        if not next_url:
            next_url = request.GET.get('next')
        if not next_url:
            next_url = request.META.get('HTTP_REFERER')
        if not next_url:
            next_url = reverse(self.default_next_view_name)

        cx = {
            'form': TwoFactorForm(data=request.POST or None),
            'next': next_url,
        }
        for k, v in kw.items():
            if v:
                cx[k] = v
        return cx

    def get(self, request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return redirect(self.logout_view_name)
        assert isinstance(user, User)

        cx = self.get_context_data()

        try:
            self.get_session(request).send_code()
        except ValidationError as e:
            logger.info('2FA_WARNING: {} / {}'.format(user, e))
            cx['error'] = ' '.join(e.messages)

        return render(request, self.template_name, cx)

    def get_session(self, request: HttpRequest, reset: bool = False) -> TwoFactorSession:
        user, ip, user_agent, phone = self.get_session_const(request)
        ses_id = request.session.get('j2fa_session')
        ses = TwoFactorSession.objects.filter(id=ses_id).first() if ses_id else None
        assert ses is None or isinstance(ses, TwoFactorSession)
        if not ses or not ses.is_valid(user, ip, user_agent) or reset:
            since = now() - timedelta(hours=24)
            if hasattr(settings, 'MAX_FAILED_ATTEMPTS_24H'):
                max_failed_attempts_24h = settings.MAX_FAILED_ATTEMPTS_24H
            else:
                max_failed_attempts_24h = DEFAULT_MAX_FAILED_ATTEMPTS_24H

            if TwoFactorSession.objects.count_failed_attempts(user, ip, since) > max_failed_attempts_24h:
                raise TwoFactorAuthError(_('Too many attempts in 24h'))

            ses = TwoFactorSession.objects.create(user=user, ip=ip, user_agent=user_agent, phone=phone, code=j2fa_make_code())
            request.session['j2fa_session'] = ses.id
        return ses

    def get_session_const(self, request: HttpRequest):
        user = request.user
        assert isinstance(user, User)
        ip = get_real_ip(request)
        if ip is None and settings.DEBUG:
            ip = '127.0.0.1'
        user_agent = request.META['HTTP_USER_AGENT']
        phone = j2fa_phone_filter(self.get_user_phone(user))
        if not phone:
            raise TwoFactorAuthError(_('your.phone.number.missing.from.system'))
        return user, ip, user_agent, phone

    def post(self, request, *args, **kwargs):  # pylint: disable=unused-argument
        cx = self.get_context_data()
        form = cx['form']
        assert isinstance(form, TwoFactorForm)

        if form.is_valid():
            try:
                ses = self.get_session(request)
                assert isinstance(ses, TwoFactorSession)
                code = form.cleaned_data['code']
                user, ip, user_agent, phone = self.get_session_const(request)
                logger.info('2FA_POST_CODE: {} {} {} "{}" vs {}'.format(user, ip, user_agent, phone, ses.code))
                if ses.code != code:
                    self.get_session(request, reset=True).send_code()
                    raise TwoFactorAuthError(_('Invalid code, sending new one'))

                logger.info('2FA_PASS: {} / {}'.format(user, ses))
                TwoFactorSession.objects.archive_old_sessions(user, ses)

                return redirect(cx.get('next'))
            except TwoFactorAuthError as e:
                form.add_error(None, e)
            except Exception as e:
                form.add_error(None, e)

        return render(request, self.template_name, cx)
