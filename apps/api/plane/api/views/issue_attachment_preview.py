# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""API-key controlled attachment-to-Page preview operations."""

from __future__ import annotations

import base64
import hashlib
import html
import json

import requests
from django.conf import settings
from django.db import transaction
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response

from plane.api.views.base import BaseAPIView
from plane.app.serializers import IssueAttachmentPreviewSerializer
from plane.db.models import FileAsset, Page, ProjectMember, ProjectPage
from plane.settings.storage import S3Storage
from plane.utils.attachment_preview import (
    PREVIEW_KIND,
    PREVIEW_KIND_KEY,
    PREVIEW_PAGE_EXTERNAL_SOURCE,
    PREVIEW_PAGE_ID,
    PreviewAttributesInvalid,
    can_read_issue,
    clear_preview_mapping,
    contains_sensitive_data,
    get_preview_attachment,
    get_preview_page,
    is_project_admin,
    resolve_preview_mapping,
    set_preview_mapping,
)
from plane.utils.content_validator import validate_binary_data, validate_html_content
from plane.utils.url import normalize_url_path


class PreviewImportError(Exception):
    def __init__(self, code, message, http_status=status.HTTP_422_UNPROCESSABLE_ENTITY):
        self.code = code
        self.message = message
        self.http_status = http_status
        super().__init__(message)


def _ready_payload(page_id, *, created=None):
    payload = {
        "preview_status": "ready",
        "preview_kind": PREVIEW_KIND,
        "preview_page_id": str(page_id),
    }
    if created is not None:
        payload["created"] = created
    return payload


def _mapping_error(code, message, preview_status="invalid"):
    return {"error": message, "code": code, "preview_status": preview_status}


def _read_text_asset(attachment, content_type):
    if attachment.size < 1 or attachment.size > settings.FILE_SIZE_LIMIT:
        raise PreviewImportError("preview_source_too_large", "Attachment size is not supported.")
    storage = S3Storage()
    try:
        response = storage.s3_client.get_object(
            Bucket=storage.aws_storage_bucket_name,
            Key=attachment.asset.name,
        )
        body = response.get("Body")
        try:
            length = response.get("ContentLength")
            stored_type = response.get("ContentType")
            if (
                body is None
                or not isinstance(length, int)
                or length < 1
                or length > settings.FILE_SIZE_LIMIT
            ):
                raise PreviewImportError(
                    "preview_source_too_large", "Attachment size is not supported."
                )
            if stored_type and stored_type != content_type:
                raise PreviewImportError(
                    "preview_source_type_mismatch",
                    "Attachment content type does not match its metadata.",
                )
            raw = body.read(settings.FILE_SIZE_LIMIT + 1)
        finally:
            if body is not None:
                body.close()
    except PreviewImportError:
        raise
    except Exception as exc:
        raise PreviewImportError(
            "preview_source_unavailable",
            "Attachment content is unavailable.",
            status.HTTP_502_BAD_GATEWAY,
        ) from exc
    if len(raw) != length or len(raw) > settings.FILE_SIZE_LIMIT:
        raise PreviewImportError("preview_source_too_large", "Attachment size is not supported.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PreviewImportError("preview_source_not_utf8", "Attachment must be valid UTF-8 text.") from exc
    if contains_sensitive_data(text):
        raise PreviewImportError(
            "contains_sensitive_data",
            "Attachment contains a high-confidence credential or private-key pattern.",
        )
    return text


def _source_identity_hash(attachment):
    """Hash the persisted source identity without reading the remote object."""

    attributes = attachment.attributes if isinstance(attachment.attributes, dict) else None
    identity = {
        "id": str(attachment.id),
        "workspace_id": str(attachment.workspace_id),
        "project_id": str(attachment.project_id),
        "issue_id": str(attachment.issue_id),
        "asset": attachment.asset.name,
        "size": attachment.size,
        "is_uploaded": attachment.is_uploaded,
        "attributes": attributes,
        "storage_metadata": attachment.storage_metadata,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _validate_image_asset(attachment, content_type):
    magic = {
        "image/jpeg": lambda prefix: prefix.startswith(b"\xff\xd8\xff"),
        "image/png": lambda prefix: prefix.startswith(b"\x89PNG\r\n\x1a\n"),
    }
    storage = S3Storage()
    try:
        metadata = storage.s3_client.head_object(
            Bucket=storage.aws_storage_bucket_name,
            Key=attachment.asset.name,
        )
        length = metadata.get("ContentLength")
        stored_type = metadata.get("ContentType")
        if (
            not isinstance(length, int)
            or length < 1
            or length > settings.FILE_SIZE_LIMIT
            or attachment.size > settings.FILE_SIZE_LIMIT
        ):
            raise PreviewImportError("preview_source_too_large", "Attachment size is not supported.")
        if stored_type and stored_type != content_type:
            raise PreviewImportError(
                "preview_source_type_mismatch",
                "Attachment content type does not match its metadata.",
            )
        response = storage.s3_client.get_object(
            Bucket=storage.aws_storage_bucket_name,
            Key=attachment.asset.name,
            Range="bytes=0-7",
        )
        body = response.get("Body")
        if body is None:
            raise PreviewImportError("preview_source_unavailable", "Attachment content is unavailable.")
        try:
            prefix = body.read(8)
        finally:
            body.close()
    except PreviewImportError:
        raise
    except Exception as exc:
        raise PreviewImportError(
            "preview_source_unavailable",
            "Attachment content is unavailable.",
            status.HTTP_502_BAD_GATEWAY,
        ) from exc
    if not magic[content_type](prefix):
        raise PreviewImportError(
            "preview_source_type_mismatch",
            "Attachment content does not match its image type.",
        )


def _convert_html(document_html):
    is_valid, error_message, sanitized_html = validate_html_content(document_html)
    if not is_valid or sanitized_html is None:
        raise PreviewImportError(
            "preview_html_invalid",
            error_message or "Generated preview HTML is invalid.",
        )
    if not settings.LIVE_URL:
        raise PreviewImportError(
            "preview_converter_unavailable",
            "Plane Live document converter is unavailable.",
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    url = normalize_url_path(f"{settings.LIVE_URL}/convert-document/")
    try:
        response = requests.post(
            url,
            json={"description_html": sanitized_html, "variant": "document"},
            timeout=20,
        )
        if response.status_code != status.HTTP_200_OK:
            raise PreviewImportError(
                "preview_conversion_failed",
                "Plane Live could not convert the attachment preview.",
                status.HTTP_502_BAD_GATEWAY,
            )
        converted = response.json()
        description_json = converted.get("description_json")
        encoded_binary = converted.get("description_binary")
        if not isinstance(description_json, dict) or not isinstance(encoded_binary, str):
            raise PreviewImportError(
                "preview_conversion_invalid",
                "Plane Live returned an invalid document payload.",
                status.HTTP_502_BAD_GATEWAY,
            )
        description_binary = base64.b64decode(encoded_binary, validate=True)
        binary_valid, _ = validate_binary_data(description_binary)
        if not binary_valid:
            raise PreviewImportError(
                "preview_conversion_invalid",
                "Plane Live returned an invalid document payload.",
                status.HTTP_502_BAD_GATEWAY,
            )
    except PreviewImportError:
        raise
    except (requests.RequestException, ValueError, TypeError) as exc:
        raise PreviewImportError(
            "preview_conversion_failed",
            "Plane Live could not convert the attachment preview.",
            status.HTTP_502_BAD_GATEWAY,
        ) from exc
    return sanitized_html, description_json, description_binary


class IssueAttachmentPreviewAPIEndpoint(BaseAPIView):
    """Resolve or mutate the controlled mapping with API-key authentication."""

    model = FileAsset

    def _member(self, request, slug, project_id):
        return ProjectMember.objects.filter(
            member=request.user,
            workspace__slug=slug,
            project_id=project_id,
            is_active=True,
            project__deleted_at__isnull=True,
            project__archived_at__isnull=True,
        ).exists()

    def get(self, request, slug, project_id, issue_id, pk):
        if not self._member(request, slug, project_id):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        attachment = get_preview_attachment(slug, project_id, issue_id, pk)
        if attachment is None:
            return Response({"error": "Issue attachment not found."}, status=status.HTTP_404_NOT_FOUND)
        if not can_read_issue(request.user, attachment.issue):
            return Response({"error": "You are not allowed to view this issue"}, status=status.HTTP_403_FORBIDDEN)
        decision = resolve_preview_mapping(
            user=request.user,
            attachment=attachment,
            slug=slug,
            project_id=project_id,
        )
        if decision.state == "not_configured":
            return Response(
                _mapping_error(decision.code, "Preview is not configured.", decision.state),
                status=status.HTTP_404_NOT_FOUND,
            )
        if decision.state == "invalid":
            return Response(
                _mapping_error(decision.code, "Preview mapping is invalid.", decision.state),
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        if decision.state == "unavailable":
            return Response(
                _mapping_error(decision.code, "Preview target is no longer available.", decision.state),
                status=status.HTTP_410_GONE,
            )
        if decision.state == "forbidden":
            return Response(
                _mapping_error(decision.code, "Preview target is not available.", decision.state),
                status=status.HTTP_403_FORBIDDEN,
            )
        return Response(_ready_payload(decision.page_id), status=status.HTTP_200_OK)

    def patch(self, request, slug, project_id, issue_id, pk):
        if not is_project_admin(request.user, slug, project_id):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        serializer = IssueAttachmentPreviewSerializer(data=request.data)
        if not serializer.is_valid():
            payload = _mapping_error("preview_mapping_invalid", "Preview mapping is invalid.")
            payload["details"] = serializer.errors
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        decision = set_preview_mapping(
            user=request.user,
            slug=slug,
            project_id=project_id,
            issue_id=issue_id,
            asset_id=pk,
            page_id=serializer.validated_data[PREVIEW_PAGE_ID],
        )
        if decision.state == "not_found":
            return Response({"error": "Issue attachment not found."}, status=status.HTTP_404_NOT_FOUND)
        if decision.state == "target_invalid":
            return Response(
                _mapping_error(
                    decision.code,
                    "Preview page must be an active public page in the same project.",
                ),
                status=status.HTTP_400_BAD_REQUEST,
            )
        if decision.state == "attributes_invalid":
            return Response(
                _mapping_error(decision.code, "Attachment attributes are invalid."),
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        return Response(_ready_payload(decision.page_id), status=status.HTTP_200_OK)

    def delete(self, request, slug, project_id, issue_id, pk):
        if not is_project_admin(request.user, slug, project_id):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        decision = clear_preview_mapping(
            slug=slug,
            project_id=project_id,
            issue_id=issue_id,
            asset_id=pk,
        )
        if decision.state == "not_found":
            return Response({"error": "Issue attachment not found."}, status=status.HTTP_404_NOT_FOUND)
        if decision.state == "attributes_invalid":
            return Response(
                _mapping_error(decision.code, "Attachment attributes are invalid."),
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        return Response(status=status.HTTP_204_NO_CONTENT)


class IssueAttachmentPreviewPageImportAPIEndpoint(BaseAPIView):
    """Create one protected Page from an attachment and map it atomically."""

    model = FileAsset
    TEXT_TYPES = {"text/plain", "text/markdown", "application/json"}
    IMAGE_TYPES = {"image/jpeg", "image/png"}

    def _mapped_page(self, attachment, slug, project_id):
        mapped_id = attachment.attributes.get(PREVIEW_PAGE_ID)
        mapped_kind = attachment.attributes.get(PREVIEW_KIND_KEY)
        if mapped_id is None and mapped_kind is None:
            return None
        serializer = IssueAttachmentPreviewSerializer(
            data={"preview_kind": mapped_kind, "preview_page_id": mapped_id}
        )
        if not serializer.is_valid():
            raise PreviewImportError("preview_mapping_invalid", "Preview mapping is invalid.")
        mapped_page = get_preview_page(slug, project_id, serializer.validated_data[PREVIEW_PAGE_ID])
        if mapped_page is None or mapped_page.access != Page.PUBLIC_ACCESS:
            raise PreviewImportError("preview_target_unavailable", "Preview target is unavailable.")
        if mapped_page.external_source == PREVIEW_PAGE_EXTERNAL_SOURCE and not mapped_page.is_locked:
            mapped_page.is_locked = True
            mapped_page.save(update_fields=["is_locked", "updated_at"])
        return mapped_page

    def _existing_page(self, attachment, project_id):
        return Page.objects.filter(
            workspace_id=attachment.workspace_id,
            external_source=PREVIEW_PAGE_EXTERNAL_SOURCE,
            external_id=str(attachment.id),
            project_pages__project_id=project_id,
            project_pages__deleted_at__isnull=True,
            archived_at__isnull=True,
        ).first()

    def _map_existing_page(self, attachment, existing):
        if existing.access != Page.PUBLIC_ACCESS:
            raise PreviewImportError("preview_target_unavailable", "Preview target is unavailable.")
        if not existing.is_locked:
            existing.is_locked = True
            existing.save(update_fields=["is_locked", "updated_at"])
        attributes = dict(attachment.attributes)
        attributes.update({PREVIEW_KIND_KEY: PREVIEW_KIND, PREVIEW_PAGE_ID: str(existing.id)})
        attachment.attributes = attributes
        attachment.save(update_fields=["attributes", "updated_at"])
        return existing

    def post(self, request, slug, project_id, issue_id, pk):
        if not is_project_admin(request.user, slug, project_id):
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        try:
            # Remote storage and Plane Live can each block. Read and convert before
            # taking the row lock, then re-check every persisted source invariant in
            # a short transaction before creating or mapping the derived Page.
            with transaction.atomic():
                attachment = get_preview_attachment(slug, project_id, issue_id, pk, for_update=True)
                if attachment is None:
                    return Response(
                        {"error": "Issue attachment not found."},
                        status=status.HTTP_404_NOT_FOUND,
                    )
                if not isinstance(attachment.attributes, dict):
                    raise PreviewImportError(
                        "attachment_attributes_invalid", "Attachment attributes are invalid."
                    )
                mapped_page = self._mapped_page(attachment, slug, project_id)
                if mapped_page is not None:
                    return Response(
                        _ready_payload(mapped_page.id, created=False),
                        status=status.HTTP_200_OK,
                    )
                existing = self._existing_page(attachment, project_id)
                if existing is not None:
                    self._map_existing_page(attachment, existing)
                    return Response(
                        _ready_payload(existing.id, created=False),
                        status=status.HTTP_200_OK,
                    )
                source_identity_hash = _source_identity_hash(attachment)

            content_type = attachment.attributes.get("type")
            if content_type in self.TEXT_TYPES:
                source_text = _read_text_asset(attachment, content_type)
                document_html = f"<pre><code>{html.escape(source_text)}</code></pre>"
            elif content_type in self.IMAGE_TYPES:
                _validate_image_asset(attachment, content_type)
                inline_path = reverse(
                    "project-issue-attachment-inline",
                    kwargs={
                        "slug": slug,
                        "project_id": project_id,
                        "issue_id": issue_id,
                        "pk": pk,
                    },
                )
                # Keep this aligned with the editor's CustomImageExtension attributes.
                # `alt` is not an image-component attribute and is deliberately omitted:
                # the HTML validator would remove it before the Live conversion.
                document_html = (
                    '<image-component status="uploaded" width="100%" height="auto" '
                    'alignment="center" '
                    f'src="{html.escape(inline_path, quote=True)}"></image-component>'
                )
            else:
                raise PreviewImportError(
                    "preview_source_unsupported",
                    "Attachment type is not supported for safe Page preview.",
                    status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                )

            clean_html, description_json, description_binary = _convert_html(document_html)
            with transaction.atomic():
                attachment = get_preview_attachment(slug, project_id, issue_id, pk, for_update=True)
                if attachment is None:
                    return Response({"error": "Issue attachment not found."}, status=status.HTTP_404_NOT_FOUND)
                if not isinstance(attachment.attributes, dict):
                    raise PreviewImportError("attachment_attributes_invalid", "Attachment attributes are invalid.")

                mapped_page = self._mapped_page(attachment, slug, project_id)
                if mapped_page is not None:
                    return Response(_ready_payload(mapped_page.id, created=False), status=status.HTTP_200_OK)

                existing = self._existing_page(attachment, project_id)
                if existing is not None:
                    self._map_existing_page(attachment, existing)
                    return Response(_ready_payload(existing.id, created=False), status=status.HTTP_200_OK)

                if _source_identity_hash(attachment) != source_identity_hash:
                    raise PreviewImportError(
                        "preview_source_changed",
                        "Attachment source changed while the preview was being prepared.",
                        status.HTTP_409_CONFLICT,
                    )

                page = Page.objects.create(
                    workspace_id=attachment.workspace_id,
                    name="附件内容预览",
                    description_json=description_json,
                    description_binary=description_binary,
                    description_html=clean_html,
                    owned_by=request.user,
                    access=Page.PUBLIC_ACCESS,
                    is_locked=True,
                    external_source=PREVIEW_PAGE_EXTERNAL_SOURCE,
                    external_id=str(attachment.id),
                    created_by=request.user,
                )
                ProjectPage.objects.create(
                    workspace_id=attachment.workspace_id,
                    project_id=project_id,
                    page=page,
                    created_by=request.user,
                )
                attributes = dict(attachment.attributes)
                attributes.update({PREVIEW_KIND_KEY: PREVIEW_KIND, PREVIEW_PAGE_ID: str(page.id)})
                attachment.attributes = attributes
                attachment.save(update_fields=["attributes", "updated_at"])
                return Response(_ready_payload(page.id, created=True), status=status.HTTP_201_CREATED)
        except PreviewImportError as exc:
            return Response(
                _mapping_error(exc.code, exc.message),
                status=exc.http_status,
            )
