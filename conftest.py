import pytest


@pytest.fixture(autouse=True)
def disable_secure_redirects(settings):
    settings.SECURE_SSL_REDIRECT = False
    settings.SESSION_COOKIE_SECURE = False
    settings.CSRF_COOKIE_SECURE = False
