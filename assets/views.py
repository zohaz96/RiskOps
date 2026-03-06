from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import Asset
from .forms import AssetForm
from users.decorators import analyst_or_above, admin_required
from audit.utils import log_action


@login_required
def asset_list(request):
    """All users can view the asset register."""
    assets = Asset.objects.select_related("owner").all()
    return render(request, "assets/asset_list.html", {"assets": assets})


@login_required
def asset_detail(request, pk):
    """All users can view asset details including linked vulnerabilities."""
    asset = get_object_or_404(Asset, pk=pk)
    vulnerabilities = asset.vulnerabilities.select_related("reported_by").all()
    return render(request, "assets/asset_detail.html", {"asset": asset, "vulnerabilities": vulnerabilities})


@login_required
@analyst_or_above
def asset_create(request):
    """Analysts, managers and admins can add new assets."""
    if request.method == "POST":
        form = AssetForm(request.POST)
        if form.is_valid():
            asset = form.save()
            log_action(request, "CREATE", "Asset", asset.id, f"Created asset: {asset.name}")
            messages.success(request, f"Asset '{asset.name}' added successfully.")
            return redirect("assets:detail", pk=asset.pk)
    else:
        form = AssetForm()
    return render(request, "assets/asset_form.html", {"form": form, "title": "Add Asset"})


@login_required
@analyst_or_above
def asset_edit(request, pk):
    """Analysts, managers and admins can edit assets."""
    asset = get_object_or_404(Asset, pk=pk)
    if request.method == "POST":
        form = AssetForm(request.POST, instance=asset)
        if form.is_valid():
            form.save()
            log_action(request, "UPDATE", "Asset", asset.id, f"Updated asset: {asset.name}")
            messages.success(request, f"Asset '{asset.name}' updated.")
            return redirect("assets:detail", pk=asset.pk)
    else:
        form = AssetForm(instance=asset)
    return render(request, "assets/asset_form.html", {"form": form, "title": "Edit Asset"})


@login_required
def asset_delete(request, pk):
    """Only admins can delete assets."""
    if not request.user.can_delete:
        messages.error(request, "You do not have permission to delete assets.")
        return redirect("assets:detail", pk=pk)
    asset = get_object_or_404(Asset, pk=pk)
    if request.method == "POST":
        name = asset.name
        asset.delete()
        log_action(request, "DELETE", "Asset", pk, f"Deleted asset: {name}")
        messages.success(request, f"Asset '{name}' deleted.")
        return redirect("assets:list")
    return render(request, "assets/asset_confirm_delete.html", {"asset": asset})