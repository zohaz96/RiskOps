import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "riskops_project.settings")
django.setup()

from users.models import User, Role
from assets.models import Asset, Environment, Criticality
from vulnerabilities.models import Vulnerability, Severity, VulnStatus

def seed():
    print("Seeding RiskOps demo data...")

    # Users
    users_data = [
        {"username": "admin", "email": "admin@riskops.local", "first_name": "Admin", "last_name": "User", "role": Role.ADMIN, "password": "AdminPass123!"},
        {"username": "s.manager", "email": "manager@riskops.local", "first_name": "Sarah", "last_name": "Manager", "role": Role.SECURITY_MANAGER, "password": "ManagerPass123!"},
        {"username": "s.analyst", "email": "analyst@riskops.local", "first_name": "John", "last_name": "Analyst", "role": Role.SECURITY_ANALYST, "password": "AnalystPass123!"},
        {"username": "auditor", "email": "auditor@riskops.local", "first_name": "Anne", "last_name": "Auditor", "role": Role.AUDITOR, "password": "AuditorPass123!"},
    ]

    created_users = {}
    for u in users_data:
        user, created = User.objects.get_or_create(username=u["username"], defaults={
            "email": u["email"],
            "first_name": u["first_name"],
            "last_name": u["last_name"],
            "role": u["role"],
            "is_staff": u["role"] == Role.ADMIN,
            "is_superuser": u["role"] == Role.ADMIN,
        })
        if created:
            user.set_password(u["password"])
            user.save()
            print(f"  User: {user.username} ({user.role}) [created]")
        else:
            print(f"  User: {user.username} ({user.role}) [already exists]")
        created_users[u["username"]] = user

    # Assets
    assets_data = [
        {"name": "Production API Gateway", "environment": Environment.PRODUCTION, "criticality": Criticality.CRITICAL, "hostname": "api-gateway.internal"},
        {"name": "Customer Database Server", "environment": Environment.PRODUCTION, "criticality": Criticality.CRITICAL, "hostname": "db-prod-01.internal"},
        {"name": "Staging Web Server", "environment": Environment.STAGING, "criticality": Criticality.HIGH, "hostname": "web-staging-01.internal"},
        {"name": "CI/CD Jenkins Server", "environment": Environment.DEVELOPMENT, "criticality": Criticality.HIGH, "hostname": "jenkins.internal"},
        {"name": "Internal HR Portal", "environment": Environment.PRODUCTION, "criticality": Criticality.MEDIUM, "hostname": "hr-portal.internal"},
        {"name": "Dev Sandbox", "environment": Environment.DEVELOPMENT, "criticality": Criticality.LOW, "hostname": "sandbox.internal"},
    ]

    created_assets = {}
    for a in assets_data:
        asset, created = Asset.objects.get_or_create(name=a["name"], defaults={
            **a, "owner": created_users["s.manager"]
        })
        print(f"  Asset: {asset.name} [{'created' if created else 'already exists'}]")
        created_assets[a["name"]] = asset

    # Vulnerabilities
    vulns_data = [
        {"title": "SQL Injection in login endpoint", "description": "User input is not sanitised before being passed to the database query, allowing an attacker to manipulate the SQL statement.", "cvss_score": 9.8, "severity": Severity.CRITICAL, "status": VulnStatus.OPEN, "asset": "Production API Gateway", "cve_reference": "CVE-2023-1234"},
        {"title": "Broken Object Level Authorisation", "description": "API endpoints do not verify that the requesting user has permission to access the requested object, allowing horizontal privilege escalation.", "cvss_score": 8.1, "severity": Severity.HIGH, "status": VulnStatus.IN_PROGRESS, "asset": "Production API Gateway"},
        {"title": "Cleartext transmission of credentials", "description": "User credentials are transmitted over HTTP rather than HTTPS on the staging environment.", "cvss_score": 7.5, "severity": Severity.HIGH, "status": VulnStatus.PENDING_APPROVAL, "asset": "Staging Web Server"},
        {"title": "Outdated OpenSSL library", "description": "The server is running OpenSSL 1.0.2 which has known vulnerabilities and is no longer receiving security updates.", "cvss_score": 6.5, "severity": Severity.MEDIUM, "status": VulnStatus.OPEN, "asset": "Customer Database Server"},
        {"title": "Default admin credentials not changed", "description": "The Jenkins server was found to be using default administrator credentials, allowing unauthorised access.", "cvss_score": 9.0, "severity": Severity.CRITICAL, "status": VulnStatus.RESOLVED, "asset": "CI/CD Jenkins Server"},
        {"title": "Missing rate limiting on password reset", "description": "The password reset endpoint does not implement rate limiting, making it vulnerable to brute force attacks.", "cvss_score": 5.3, "severity": Severity.MEDIUM, "status": VulnStatus.OPEN, "asset": "Internal HR Portal"},
        {"title": "Verbose error messages in production", "description": "Detailed stack traces and database error messages are exposed to end users, leaking internal system information.", "cvss_score": 4.0, "severity": Severity.LOW, "status": VulnStatus.OPEN, "asset": "Production API Gateway"},
        {"title": "Missing HSTS header", "description": "The application does not set the HTTP Strict Transport Security header, leaving users vulnerable to SSL stripping attacks.", "cvss_score": 3.7, "severity": Severity.LOW, "status": VulnStatus.OPEN, "asset": "Staging Web Server"},
        {"title": "Insecure Direct Object Reference in file download", "description": "File download endpoint accepts a user-supplied file ID without verifying the requesting user has permission to access that file.", "cvss_score": 7.2, "severity": Severity.HIGH, "status": VulnStatus.OPEN, "asset": "Internal HR Portal"},
        {"title": "Session token not invalidated on logout", "description": "Session tokens remain valid after logout, allowing reuse if intercepted.", "cvss_score": 6.1, "severity": Severity.MEDIUM, "status": VulnStatus.IN_PROGRESS, "asset": "Production API Gateway"},
    ]

    for v in vulns_data:
        asset = created_assets[v.pop("asset")]
        vuln, created = Vulnerability.objects.get_or_create(title=v["title"], defaults={
            **v, "asset": asset, "reported_by": created_users["s.analyst"],
        })
        print(f"  Vuln: {vuln.title} [{'created' if created else 'already exists'}]")

    print("\nSeeding complete.")
    print("Demo credentials:")
    print("  admin / AdminPass123! (Admin)")
    print("  s.manager / ManagerPass123! (Security Manager)")
    print("  s.analyst / AnalystPass123! (Security Analyst)")
    print("  auditor / AuditorPass123! (Auditor)")

if __name__ == "__main__":
    seed()