import pytest
from django.test import Client
from django.urls import reverse
from users.models import User, Role
from assets.models import Asset, Environment, Criticality
from vulnerabilities.models import Vulnerability, Severity, VulnStatus
from vulnerabilities.forms import VulnerabilityForm


# ── Fixtures ────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    return Client()


@pytest.fixture
def admin_user(db):
    user = User.objects.create_user(
        username="testadmin",
        email="admin@test.local",
        password="AdminPass123!",
        role=Role.ADMIN,
        is_staff=True,
        is_superuser=True,
    )
    return user


@pytest.fixture
def analyst_user(db):
    return User.objects.create_user(
        username="testanalyst",
        email="analyst@test.local",
        password="AnalystPass123!",
        role=Role.SECURITY_ANALYST,
    )


@pytest.fixture
def auditor_user(db):
    return User.objects.create_user(
        username="testauditor",
        email="auditor@test.local",
        password="AuditorPass123!",
        role=Role.AUDITOR,
    )


@pytest.fixture
def sample_asset(db, admin_user):
    return Asset.objects.create(
        name="Test Server",
        environment=Environment.PRODUCTION,
        criticality=Criticality.HIGH,
        owner=admin_user,
    )


@pytest.fixture
def sample_vuln(db, admin_user, sample_asset):
    return Vulnerability.objects.create(
        title="Test Vulnerability",
        description="A test vulnerability.",
        cvss_score=7.5,
        severity=Severity.HIGH,
        status=VulnStatus.OPEN,
        asset=sample_asset,
        reported_by=admin_user,
    )


# ── Authentication Tests ────────────────────────────────────────────

class TestAuthentication:

    def test_unauthenticated_redirects_to_login(self, client):
        """Unauthenticated users must be redirected — OWASP A07."""
        response = client.get(reverse("core:dashboard"))
        assert response.status_code == 302
        assert "/users/login/" in response["Location"]

    def test_login_succeeds_with_valid_credentials(self, client, admin_user):
        """Valid credentials should log the user in."""
        response = client.post(reverse("users:login"), {
            "username": "testadmin",
            "password": "AdminPass123!",
        })
        assert response.status_code == 302

    def test_login_fails_with_invalid_credentials(self, client, admin_user):
        """Invalid credentials must not authenticate — OWASP A07."""
        response = client.post(reverse("users:login"), {
            "username": "testadmin",
            "password": "wrongpassword",
        })
        assert response.status_code == 200  # stays on login page


# ── Authorisation Tests ───────────────────────────────────────────────────────

class TestAuthorisation:

    def test_auditor_cannot_access_user_management(self, client, auditor_user):
        """Auditors must not access user management — OWASP A01."""
        client.force_login(auditor_user)
        response = client.get(reverse("users:user_list"))
        assert response.status_code == 403

    def test_auditor_cannot_access_audit_log(self, client, auditor_user):
        """Only admins can view audit log — OWASP A01."""
        client.force_login(auditor_user)
        response = client.get(reverse("audit:logs"))
        assert response.status_code == 403

    def test_analyst_cannot_access_user_management(self, client, analyst_user):
        """Analysts must not access user management — OWASP A01."""
        client.force_login(analyst_user)
        response = client.get(reverse("users:user_list"))
        assert response.status_code == 403

    def test_admin_can_access_user_management(self, client, admin_user):
        """Admins can access user management."""
        client.force_login(admin_user)
        response = client.get(reverse("users:user_list"))
        assert response.status_code == 200


# ── Input Validation Tests ─────────────────────────────────────────────────

class TestInputValidation:

    def test_cvss_score_above_10_rejected(self, db, admin_user, sample_asset):
        """CVSS score above 10 must be rejected — OWASP A03."""
        form = VulnerabilityForm(data={
            "title": "Test",
            "description": "Test",
            "cvss_score": 11.0,
            "severity": Severity.HIGH,
            "status": VulnStatus.OPEN,
            "asset": sample_asset.pk,
        })
        assert not form.is_valid()

    def test_invalid_cve_format_rejected(self, db, admin_user, sample_asset):
        """Malformed CVE references must be rejected — OWASP A03."""
        form = VulnerabilityForm(data={
            "title": "Test",
            "description": "Test",
            "cvss_score": 5.0,
            "severity": Severity.MEDIUM,
            "status": VulnStatus.OPEN,
            "asset": sample_asset.pk,
            "cve_reference": "NOT-A-CVE",
        })
        assert not form.is_valid()
        assert "cve_reference" in form.errors

    def test_valid_cve_format_accepted(self, db, admin_user, sample_asset):
        """Correctly formatted CVE references must be accepted."""
        form = VulnerabilityForm(data={
            "title": "Test",
            "description": "Test",
            "cvss_score": 5.0,
            "severity": Severity.MEDIUM,
            "status": VulnStatus.OPEN,
            "asset": sample_asset.pk,
            "cve_reference": "CVE-2024-1234",
        })
        assert form.is_valid()


# ── Audit Log Tests ──────────────────────────────────────────

class TestAuditLog:

    def test_vulnerability_creation_logged(self, client, analyst_user, sample_asset):
        """Creating a vulnerability must generate an audit log entry — OWASP A09."""
        from audit.models import AuditLog
        client.force_login(analyst_user)
        client.post(reverse("vulnerabilities:create"), {
            "title": "Logged Vuln",
            "description": "Test",
            "cvss_score": 5.0,
            "severity": Severity.MEDIUM,
            "status": VulnStatus.OPEN,
            "asset": sample_asset.pk,
        })
        assert AuditLog.objects.filter(action="CREATE", entity_type="Vulnerability").exists()