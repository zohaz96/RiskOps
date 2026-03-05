from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import Asset


@login_required
def asset_list(request):
    assets = Asset.objects.select_related("owner").all()
    return render(request, "assets/asset_list.html", {"assets": assets})