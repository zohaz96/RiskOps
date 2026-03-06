from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from .models import Vulnerability, VulnStatus
from .forms import VulnerabilityForm
from users.decorators import analyst_or_above, manager_or_above
from audit.utils import log_action


@login_required
def vulnerability_list(request):
    """All users can view the vulnerability list."""
    vulnerabilities = Vulnerability.objects.select_related("asset", "reported_by").all()
    return render(request, "vulnerabilities/vulnerability_list.html", {"vulnerabilities": vulnerabilities})


@login_required
def vulnerability_detail(request, pk):
    """All users can view vulnerability details."""
    vuln = get_object_or_404(Vulnerability, pk=pk)
    return render(request, "vulnerabilities/vulnerability_detail.html", {"vuln": vuln})


@login_required
@analyst_or_above
def vulnerability_create(request):
    """Analysts, managers and admins can report new vulnerabilities."""
    if request.method == "POST":
        form = VulnerabilityForm(request.POST)
        if form.is_valid():
            vuln = form.save(commit=False)
            vuln.reported_by = request.user
            vuln.save()
            log_action(request, "CREATE", "Vulnerability", vuln.id, f"Reported vulnerability: {vuln.title}")
            messages.success(request, f"Vulnerability '{vuln.title}' reported successfully.")
            return redirect("vulnerabilities:detail", pk=vuln.pk)
    else:
        form = VulnerabilityForm()
    return render(request, "vulnerabilities/vulnerability_form.html", {"form": form, "title": "Report Vulnerability"})


@login_required
@analyst_or_above
def vulnerability_edit(request, pk):
    """
    Analysts can only edit their own vulnerabilities.
    Managers and admins can edit any vulnerability.
    This enforces object-level access control (OWASP A01).
    """
    vuln = get_object_or_404(Vulnerability, pk=pk)

    # Object-level check — analysts can only edit their own reports
    if request.user.is_security_analyst and vuln.reported_by != request.user:
        messages.error(request, "You can only edit vulnerabilities you reported.")
        return redirect("vulnerabilities:detail", pk=vuln.pk)

    if request.method == "POST":
        form = VulnerabilityForm(request.POST, instance=vuln)
        if form.is_valid():
            form.save()
            log_action(request, "UPDATE", "Vulnerability", vuln.id, f"Updated vulnerability: {vuln.title}")
            messages.success(request, f"Vulnerability '{vuln.title}' updated.")
            return redirect("vulnerabilities:detail", pk=vuln.pk)
    else:
        form = VulnerabilityForm(instance=vuln)
    return render(request, "vulnerabilities/vulnerability_form.html", {"form": form, "title": "Edit Vulnerability"})


@login_required
@manager_or_above
def vulnerability_approve(request, pk):
    """Only managers and admins can approve or close vulnerabilities — separation of duties."""
    vuln = get_object_or_404(Vulnerability, pk=pk)
    if request.method == "POST":
        new_status = request.POST.get("status")
        if new_status in [VulnStatus.RESOLVED, VulnStatus.CLOSED, VulnStatus.IN_PROGRESS]:
            vuln.status = new_status
            vuln.approved_by = request.user
            vuln.approved_at = timezone.now()
            vuln.save()
            log_action(request, "APPROVE", "Vulnerability", vuln.id, f"Status updated to {new_status}: {vuln.title}")
            messages.success(request, f"Vulnerability status updated to {vuln.get_status_display()}.")
        return redirect("vulnerabilities:detail", pk=vuln.pk)
    return render(request, "vulnerabilities/vulnerability_approve.html", {"vuln": vuln})


@login_required
def vulnerability_delete(request, pk):
    """Only admins can delete vulnerabilities."""
    if not request.user.can_delete:
        messages.error(request, "You do not have permission to delete vulnerabilities.")
        return redirect("vulnerabilities:detail", pk=pk)
    vuln = get_object_or_404(Vulnerability, pk=pk)
    if request.method == "POST":
        title = vuln.title
        vuln.delete()
        log_action(request, "DELETE", "Vulnerability", pk, f"Deleted vulnerability: {title}")
        messages.success(request, f"Vulnerability '{title}' deleted.")
        return redirect("vulnerabilities:list")
    return render(request, "vulnerabilities/vulnerability_confirm_delete.html", {"vuln": vuln})