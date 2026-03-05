from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from vulnerabilities.models import Vulnerability, Severity, VulnStatus
from assets.models import Asset


@login_required
def dashboard(request):
    """Main dashboard — shows security metrics overview."""
    context = {
        "critical_count": Vulnerability.objects.filter(severity=Severity.CRITICAL, status=VulnStatus.OPEN).count(),
        "open_count": Vulnerability.objects.filter(status=VulnStatus.OPEN).count(),
        "pending_count": Vulnerability.objects.filter(status=VulnStatus.PENDING_APPROVAL).count(),
        "asset_count": Asset.objects.count(),
        "recent_vulns": Vulnerability.objects.select_related("asset", "reported_by").order_by("-discovered_at")[:5],
    }
    return render(request, "core/dashboard.html", context)