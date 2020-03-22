django-j2fa
===========

2-factor SMS authentication for Django projects. Supports Django 3.0.

Install
=======

1. Add 'j2fa' to project settings INSTALLED_APPS
2. Add j2fa.middleware.Ensure2FactorAuthenticatedMiddleware to project settings MIDDLEWARE (after session middleware)
3. Make sure user.profile.phone resolves to phone number and user.profile.require_2fa resolves to True/False
4. Set project settings SMS_TOKEN and SMS_SENDER_NAME
5. Add TwoFactorAuth.as_view() to urls with name='j2fa-obtain-auth'
