from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import Vulnerability


@login_required
def vulnerability_list(request):
    vulnerabilities = Vulnerability.objects.select_related("asset", "reported_by").all()
    return render(request, "vulnerabilities/vulnerability_list.html", {"vulnerabilities": vulnerabilities})