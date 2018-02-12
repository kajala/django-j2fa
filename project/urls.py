from django.urls import reverse_lazy
from django.views.generic import RedirectView
from j2fa.views import TwoFactorAuth
from django.conf.urls import url
from django.contrib import admin


urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^2fa/$', TwoFactorAuth.as_view(), name='j2fa-obtain-auth'),
    url(r'^$', RedirectView.as_view(url=reverse_lazy('admin:login'))),
]
