# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Shared policy helpers for issue-attachment backed Plane Page previews."""

from __future__ import annotations

import re
from dataclasses import dataclass
from uuid import UUID

from django.db import transaction

from plane.db.models import FileAsset, Page, ProjectMember, WorkspaceMember


PREVIEW_KIND = "plane_page"
PREVIEW_PAGE_ID = "preview_page_id"
PREVIEW_KIND_KEY = "preview_kind"
PREVIEW_PAGE_EXTERNAL_SOURCE = "issue_attachment_preview"


@dataclass(frozen=True)
class PreviewMappingDecision:
    """Transport-neutral outcome of resolving one attachment preview mapping."""

    state: str
    code: str | None = None
    page_id: UUID | None = None
    reason: str | None = None


class PreviewAttributesInvalid(ValueError):
    """Raised when stored attachment attributes cannot be safely transformed."""


def get_preview_attachment(
    slug,
    project_id,
    issue_id,
    asset_id,
    *,
    for_update=False,
):
    """Resolve one active uploaded issue attachment inside its exact boundary."""

    queryset = FileAsset.objects.select_related("issue", "project", "workspace")
    if for_update:
        queryset = queryset.select_for_update(of=("self",))
    return queryset.filter(
        pk=asset_id,
        workspace__slug=slug,
        project_id=project_id,
        issue_id=issue_id,
        entity_type=FileAsset.EntityTypeContext.ISSUE_ATTACHMENT,
        deleted_at__isnull=True,
        is_deleted=False,
        is_archived=False,
        is_uploaded=True,
        issue__deleted_at__isnull=True,
        issue__archived_at__isnull=True,
        project__deleted_at__isnull=True,
        project__archived_at__isnull=True,
    ).first()


def get_preview_page(slug, project_id, page_id):
    """Resolve an active Page linked to the exact active project."""

    return Page.objects.filter(
        pk=page_id,
        workspace__slug=slug,
        project_pages__project_id=project_id,
        project_pages__deleted_at__isnull=True,
        project_pages__project__deleted_at__isnull=True,
        project_pages__project__archived_at__isnull=True,
        archived_at__isnull=True,
    ).first()


def can_read_issue(user, issue):
    """Mirror the restricted Guest rule used by issue detail and attachments."""

    # Import lazily: plane.app.permissions.__init__ imports the Page permission,
    # which itself imports this helper. A module-level ROLE import therefore
    # makes direct utility imports depend on a partially initialized module.
    from plane.app.permissions.base import ROLE

    is_restricted_guest = ProjectMember.objects.filter(
        workspace_id=issue.workspace_id,
        project_id=issue.project_id,
        member=user,
        role=ROLE.GUEST.value,
        is_active=True,
    ).exists() and not WorkspaceMember.objects.filter(
        workspace_id=issue.workspace_id,
        member=user,
        role=ROLE.ADMIN.value,
        is_active=True,
    ).exists()
    is_restricted_guest = is_restricted_guest and not issue.project.guest_view_all_features
    return not is_restricted_guest or issue.created_by_id == user.id


def is_project_admin(user, slug, project_id):
    """Mirror ``allow_permission([ROLE.ADMIN])`` including its workspace fallback."""

    from plane.app.permissions.base import ROLE
    if ProjectMember.objects.filter(
        member=user,
        workspace__slug=slug,
        project_id=project_id,
        role=ROLE.ADMIN.value,
        is_active=True,
    ).exists():
        return True
    return ProjectMember.objects.filter(
        member=user,
        workspace__slug=slug,
        project_id=project_id,
        is_active=True,
    ).exists() and WorkspaceMember.objects.filter(
        member=user,
        workspace__slug=slug,
        role=ROLE.ADMIN.value,
        is_active=True,
    ).exists()


def preview_source_asset(page):
    """Return the immutable source marker's asset, including soft-deleted rows.

    A derived Page keeps its source identity in Page.external_source/external_id,
    independent of the user-facing mapping. This prevents clearing a mapping or
    soft deleting the source from silently turning derived content into an
    ordinary public Page.
    """

    if page.external_source != PREVIEW_PAGE_EXTERNAL_SOURCE or not page.external_id:
        return None
    try:
        asset_id = UUID(str(page.external_id))
    except (TypeError, ValueError):
        return False
    return (
        FileAsset.all_objects.select_related("issue", "project", "workspace")
        .filter(
            pk=asset_id,
            workspace_id=page.workspace_id,
            entity_type=FileAsset.EntityTypeContext.ISSUE_ATTACHMENT,
        )
        .first()
        or False
    )


def preview_page_access_decision(user, page, project_id):
    """Return None for normal Pages, otherwise allow/deny a derived preview.

    Deleted or detached sources fail closed. For a live source, the Page follows
    the exact issue visibility rule, including restricted Guest ownership.
    """

    asset = preview_source_asset(page)
    if asset is None:
        return None
    if asset is False:
        return False
    issue = asset.issue
    project = asset.project
    if (
        str(asset.project_id) != str(project_id)
        or asset.deleted_at is not None
        or asset.is_deleted
        or asset.is_archived
        or not asset.is_uploaded
        or issue is None
        or issue.deleted_at is not None
        or issue.archived_at is not None
        or project is None
        or project.deleted_at is not None
        or project.archived_at is not None
    ):
        return False
    return can_read_issue(user, issue)


def can_read_project_page(user, page, project_id):
    """Apply the effective read ACL for one Page in a project.

    This is shared by Page endpoints and attachment-preview resolvers so a
    resolver never advertises a Page as ready when the same caller cannot open
    the Page. Derived Pages follow their source issue ACL. Ordinary public
    Pages additionally honor the restricted Guest visibility setting.
    """

    from plane.app.permissions.base import ROLE

    membership = (
        ProjectMember.objects.filter(
            member=user,
            workspace_id=page.workspace_id,
            project_id=project_id,
            is_active=True,
            project__deleted_at__isnull=True,
            project__archived_at__isnull=True,
        )
        .values("role", "project__guest_view_all_features")
        .first()
    )
    if membership is None:
        return False

    preview_access = preview_page_access_decision(user, page, project_id)
    if preview_access is not None:
        return preview_access

    if page.owned_by_id == user.id:
        return True
    if page.access != Page.PUBLIC_ACCESS:
        return False

    if WorkspaceMember.objects.filter(
        member=user,
        workspace_id=page.workspace_id,
        role=ROLE.ADMIN.value,
        is_active=True,
    ).exists():
        return True

    role = membership["role"]
    if role == ROLE.GUEST.value and not membership["project__guest_view_all_features"]:
        return False
    return role in (ROLE.ADMIN.value, ROLE.MEMBER.value, ROLE.GUEST.value)


def resolve_preview_mapping(*, user, attachment, slug, project_id):
    """Resolve a stored mapping without coupling policy to an HTTP adapter."""

    attributes = attachment.attributes
    if attributes is None:
        attributes = {}
    elif not isinstance(attributes, dict):
        return PreviewMappingDecision(
            state="invalid",
            code="preview_mapping_invalid",
            reason="attributes_type",
        )

    preview_kind = attributes.get(PREVIEW_KIND_KEY)
    preview_page_id = attributes.get(PREVIEW_PAGE_ID)
    if preview_kind is None and preview_page_id is None:
        return PreviewMappingDecision(
            state="not_configured",
            code="preview_not_configured",
        )
    if preview_kind != PREVIEW_KIND:
        return PreviewMappingDecision(
            state="invalid",
            code="preview_mapping_invalid",
            reason="mapping_value",
        )
    try:
        preview_page_id = UUID(str(preview_page_id))
    except (TypeError, ValueError, AttributeError):
        return PreviewMappingDecision(
            state="invalid",
            code="preview_mapping_invalid",
            reason="mapping_value",
        )

    page = get_preview_page(slug, project_id, preview_page_id)
    if page is None:
        return PreviewMappingDecision(
            state="unavailable",
            code="preview_target_unavailable",
        )
    if page.access != Page.PUBLIC_ACCESS:
        return PreviewMappingDecision(
            state="forbidden",
            code="preview_target_forbidden",
            reason="target_not_public",
        )
    if not can_read_project_page(user, page, project_id):
        return PreviewMappingDecision(
            state="forbidden",
            code="preview_target_forbidden",
            reason="page_acl",
        )
    return PreviewMappingDecision(state="ready", page_id=page.id)


def with_preview_mapping(attributes, page_id):
    """Return a copied attributes mapping with a validated Page reference."""

    if attributes is None:
        attributes = {}
    if not isinstance(attributes, dict):
        raise PreviewAttributesInvalid("Attachment attributes are invalid.")
    updated = dict(attributes)
    updated.update(
        {
            PREVIEW_KIND_KEY: PREVIEW_KIND,
            PREVIEW_PAGE_ID: str(page_id),
        }
    )
    return updated


def without_preview_mapping(attributes):
    """Return a copied attributes mapping without controlled preview keys."""

    if attributes is None:
        attributes = {}
    if not isinstance(attributes, dict):
        raise PreviewAttributesInvalid("Attachment attributes are invalid.")
    updated = dict(attributes)
    updated.pop(PREVIEW_KIND_KEY, None)
    updated.pop(PREVIEW_PAGE_ID, None)
    return updated


def set_preview_mapping(
    *,
    user,
    slug,
    project_id,
    issue_id,
    asset_id,
    page_id,
):
    """Validate and persist one attachment-to-Page mapping atomically."""

    with transaction.atomic():
        attachment = get_preview_attachment(
            slug,
            project_id,
            issue_id,
            asset_id,
            for_update=True,
        )
        if attachment is None:
            return PreviewMappingDecision(
                state="not_found",
                code="attachment_not_found",
            )

        page = get_preview_page(slug, project_id, page_id)
        if (
            page is None
            or page.access != Page.PUBLIC_ACCESS
            or not can_read_project_page(user, page, project_id)
        ):
            return PreviewMappingDecision(
                state="target_invalid",
                code="preview_target_invalid",
            )

        try:
            attributes = with_preview_mapping(attachment.attributes, page.id)
        except PreviewAttributesInvalid:
            return PreviewMappingDecision(
                state="attributes_invalid",
                code="attachment_attributes_invalid",
            )
        attachment.attributes = attributes
        attachment.save(update_fields=["attributes", "updated_at"])
        return PreviewMappingDecision(state="ready", page_id=page.id)


def clear_preview_mapping(*, slug, project_id, issue_id, asset_id):
    """Remove only controlled preview keys from one locked attachment row."""

    with transaction.atomic():
        attachment = get_preview_attachment(
            slug,
            project_id,
            issue_id,
            asset_id,
            for_update=True,
        )
        if attachment is None:
            return PreviewMappingDecision(
                state="not_found",
                code="attachment_not_found",
            )
        try:
            attributes = without_preview_mapping(attachment.attributes)
        except PreviewAttributesInvalid:
            return PreviewMappingDecision(
                state="attributes_invalid",
                code="attachment_attributes_invalid",
            )
        attachment.attributes = attributes
        attachment.save(update_fields=["attributes", "updated_at"])
        return PreviewMappingDecision(state="ready")


_SENSITIVE_PATTERNS = (
    re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(
        r"(?:api[_ -]?key|client[_ -]?secret|access[_ -]?token|password|passwd)"
        r"\s*[=:]\s*[\"']?[A-Za-z0-9_./+=-]{16,}",
        re.IGNORECASE,
    ),
)


def contains_sensitive_data(text):
    """Detect only high-confidence plaintext credential/private-key shapes."""

    return any(pattern.search(text) for pattern in _SENSITIVE_PATTERNS)
