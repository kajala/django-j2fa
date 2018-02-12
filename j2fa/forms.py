from django import forms
from django.utils.translation import ugettext_lazy as _


class TwoFactorForm(forms.Form):
    code = forms.CharField(label=_('two.factor.code.label'), max_length=8, min_length=1)
