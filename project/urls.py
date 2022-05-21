from django.urls import reverse_lazy, path
from django.views.generic import RedirectView
from j2fa.views import TwoFactorAuth
from django.contrib import admin


urlpatterns = [
    path("admin/", admin.site.urls),
    path("2fa/", TwoFactorAuth.as_view(), name="j2fa-obtain-auth"),
    path("", RedirectView.as_view(url=reverse_lazy("admin:login"))),
]
