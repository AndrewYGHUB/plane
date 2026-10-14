# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import json
import uuid
from urllib.parse import quote

# Django imports
from django.utils import timezone
from django.core.serializers.json import DjangoJSONEncoder
from django.conf import settings
from django.http import HttpResponseRedirect, StreamingHttpResponse

from botocore.exceptions import BotoCoreError, ClientError

# Third Party imports
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser

# Module imports
from .. import BaseAPIView
from plane.app.serializers import (
    IssueAttachmentPreviewSerializer,
    IssueAttachmentSerializer,
)
from plane.db.models import FileAsset, Issue, Workspace
from plane.bgtasks.issue_activities_task import issue_activity
from plane.app.permissions import allow_permission, ROLE
from plane.settings.storage import S3Storage
from plane.utils.path_validator import sanitize_filename
from plane.bgtasks.storage_metadata_task import get_asset_object_metadata
from plane.utils.host import base_host
from plane.utils.attachment_preview import (
    can_read_issue,
    clear_preview_mapping,
    get_preview_attachment,
    resolve_preview_mapping,
    set_preview_mapping,
)


class IssueAttachmentEndpoint(BaseAPIView):
    serializer_class = IssueAttachmentSerializer
    model = FileAsset
    parser_classes = (MultiPartParser, FormParser)

    @allow_permission([ROLE.ADMIN, ROLE.MEMBER, ROLE.GUEST])
    def post(self, request, slug, project_id, issue_id):
        serializer = IssueAttachmentSerializer(data=request.data)
        workspace = Workspace.objects.get(slug=slug)
        if serializer.is_valid():
            serializer.save(
                project_id=project_id,
                issue_id=issue_id,
                workspace_id=workspace.id,
                entity_type=FileAsset.EntityTypeContext.ISSUE_ATTACHMENT,
            )
            issue_activity.delay(
                type="attachment.activity.created",
                requested_data=None,
                actor_id=str(self.request.user.id),
                issue_id=str(self.kwargs.get("issue_id", None)),
                project_id=str(self.kwargs.get("project_id", None)),
                current_instance=json.dumps(serializer.data, cls=DjangoJSONEncoder),
                epoch=int(timezone.now().timestamp()),
                notification=True,
                origin=base_host(request=request, is_app=True),
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @allow_permission([ROLE.ADMIN], creator=True, model=FileAsset)
    def delete(self, request, slug, project_id, issue_id, pk):
        issue_attachment = FileAsset.objects.filter(
            pk=pk, workspace__slug=slug, project_id=project_id, issue_id=issue_id
        ).first()
        if not issue_attachment:
            return Response(
                {"error": "Issue attachment not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        issue_attachment.asset.delete(save=False)
        issue_attachment.delete()
        issue_activity.delay(
            type="attachment.activity.deleted",
            requested_data=None,
            actor_id=str(self.request.user.id),
            issue_id=str(self.kwargs.get("issue_id", None)),
            project_id=str(self.kwargs.get("project_id", None)),
            current_instance=None,
            epoch=int(timezone.now().timestamp()),
            notification=True,
            origin=base_host(request=request, is_app=True),
        )

        return Response(status=status.HTTP_204_NO_CONTENT)

    @allow_permission([ROLE.ADMIN, ROLE.MEMBER, ROLE.GUEST])
    def get(self, request, slug, project_id, issue_id):
        issue = Issue.objects.select_related("project").filter(
            pk=issue_id,
            workspace__slug=slug,
            project_id=project_id,
            archived_at__isnull=True,
            project__deleted_at__isnull=True,
            project__archived_at__isnull=True,
        ).first()
        if issue is None:
            return Response(
                {"error": "The required object does not exist."},
                status=status.HTTP_404_NOT_FOUND,
            )
        if not can_read_issue(request.user, issue):
            return Response(
                {"error": "You are not allowed to view this issue"},
                status=status.HTTP_403_FORBIDDEN,
            )
        issue_attachments = FileAsset.objects.filter(issue_id=issue_id, workspace__slug=slug, project_id=project_id)
        serializer = IssueAttachmentSerializer(issue_attachments, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class IssueAttachmentV2Endpoint(BaseAPIView):
    serializer_class = IssueAttachmentSerializer
    model = FileAsset

    @allow_permission([ROLE.ADMIN, ROLE.MEMBER, ROLE.GUEST])
    def post(self, request, slug, project_id, issue_id):
        name = sanitize_filename(request.data.get("name")) or "unnamed"
        type = request.data.get("type", False)
        size = int(request.data.get("size", settings.FILE_SIZE_LIMIT))

        if not type or type not in settings.ATTACHMENT_MIME_TYPES:
            return Response(
                {"error": "Invalid file type.", "status": False},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Get the workspace
        workspace = Workspace.objects.get(slug=slug)

        # asset key
        asset_key = f"{workspace.id}/{uuid.uuid4().hex}-{name}"

        # Get the size limit
        size_limit = min(size, settings.FILE_SIZE_LIMIT)

        # Create a File Asset
        asset = FileAsset.objects.create(
            attributes={"name": name, "type": type, "size": size_limit},
            asset=asset_key,
            size=size_limit,
            workspace_id=workspace.id,
            created_by=request.user,
            issue_id=issue_id,
            project_id=project_id,
            entity_type=FileAsset.EntityTypeContext.ISSUE_ATTACHMENT,
        )

        # Get the presigned URL
        storage = S3Storage(request=request)

        # Generate a presigned URL to share an S3 object
        presigned_url = storage.generate_presigned_post(object_name=asset_key, file_type=type, file_size=size_limit)

        # Return the presigned URL
        return Response(
            {
                "upload_data": presigned_url,
                "asset_id": str(asset.id),
                "attachment": IssueAttachmentSerializer(asset).data,
                "asset_url": asset.asset_url,
            },
            status=status.HTTP_200_OK,
        )

    @allow_permission([ROLE.ADMIN], creator=True, model=FileAsset)
    def delete(self, request, slug, project_id, issue_id, pk):
        issue_attachment = FileAsset.objects.get(
            pk=pk, workspace__slug=slug, project_id=project_id, issue_id=issue_id
        )
        issue_attachment.is_deleted = True
        issue_attachment.deleted_at = timezone.now()
        issue_attachment.save()

        issue_activity.delay(
            type="attachment.activity.deleted",
            requested_data=None,
            actor_id=str(self.request.user.id),
            issue_id=str(issue_id),
            project_id=str(project_id),
            current_instance=None,
            epoch=int(timezone.now().timestamp()),
            notification=True,
            origin=base_host(request=request, is_app=True),
        )

        return Response(status=status.HTTP_204_NO_CONTENT)

    @allow_permission([ROLE.ADMIN, ROLE.MEMBER, ROLE.GUEST])
    def get(self, request, slug, project_id, issue_id, pk=None):
        issue = Issue.objects.select_related("project").filter(
            pk=issue_id,
            workspace__slug=slug,
            project_id=project_id,
            archived_at__isnull=True,
            project__deleted_at__isnull=True,
            project__archived_at__isnull=True,
        ).first()
        if issue is None:
            return Response(
                {"error": "The required object does not exist."},
                status=status.HTTP_404_NOT_FOUND,
            )
        if not can_read_issue(request.user, issue):
            return Response(
                {"error": "You are not allowed to view this issue"},
                status=status.HTTP_403_FORBIDDEN,
            )

        if pk:
            # Get the asset
            asset = FileAsset.objects.get(id=pk, workspace__slug=slug, project_id=project_id, issue_id=issue_id)

            # Check if the asset is uploaded
            if not asset.is_uploaded:
                return Response(
                    {"error": "The asset is not uploaded.", "status": False},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            storage = S3Storage(request=request)
            presigned_url = storage.generate_presigned_url(
                object_name=asset.asset.name,
                disposition="attachment",
                filename=asset.attributes.get("name"),
            )
            return HttpResponseRedirect(presigned_url)

        # Get all the attachments
        issue_attachments = FileAsset.objects.filter(
            issue_id=issue_id,
            entity_type=FileAsset.EntityTypeContext.ISSUE_ATTACHMENT,
            workspace__slug=slug,
            project_id=project_id,
            is_uploaded=True,
        )
        # Serialize the attachments
        serializer = IssueAttachmentSerializer(issue_attachments, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @allow_permission([ROLE.ADMIN, ROLE.MEMBER, ROLE.GUEST])
    def patch(self, request, slug, project_id, issue_id, pk):
        issue_attachment = FileAsset.objects.get(
            pk=pk, workspace__slug=slug, project_id=project_id, issue_id=issue_id
        )
        serializer = IssueAttachmentSerializer(issue_attachment)

        # Send this activity only if the attachment is not uploaded before
        if not issue_attachment.is_uploaded:
            issue_activity.delay(
                type="attachment.activity.created",
                requested_data=None,
                actor_id=str(self.request.user.id),
                issue_id=str(self.kwargs.get("issue_id", None)),
                project_id=str(self.kwargs.get("project_id", None)),
                current_instance=json.dumps(serializer.data, cls=DjangoJSONEncoder),
                epoch=int(timezone.now().timestamp()),
                notification=True,
                origin=base_host(request=request, is_app=True),
            )

            # Update the attachment — do NOT overwrite created_by; it is set at
            # creation time and must not be reassigned (GHSA-5mxw-g5mw-3v3w).
            issue_attachment.is_uploaded = True

        # Get the storage metadata
        if not issue_attachment.storage_metadata:
            get_asset_object_metadata.delay(str(issue_attachment.id))
        issue_attachment.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class IssueAttachmentPreviewEndpoint(BaseAPIView):
    """Manage and resolve a controlled attachment-to-Plane-Page preview.

    The mapping lives in ``FileAsset.attributes`` so the original attachment
    identity and storage metadata remain unchanged. The endpoint never accepts
    or returns an arbitrary URL: callers receive only a validated Plane Page
    identifier and construct the internal project route themselves.
    """

    model = FileAsset

    @staticmethod
    def _attachment(slug, project_id, issue_id, pk, *, for_update=False):
        return get_preview_attachment(
            slug,
            project_id,
            issue_id,
            pk,
            for_update=for_update,
        )

    @staticmethod
    def _ready_response(page_id):
        return Response(
            {
                "preview_status": "ready",
                "preview_kind": "plane_page",
                "preview_page_id": str(page_id),
            },
            status=status.HTTP_200_OK,
        )

    @allow_permission([ROLE.ADMIN, ROLE.MEMBER, ROLE.GUEST])
    def get(self, request, slug, project_id, issue_id, pk):
        attachment = self._attachment(slug, project_id, issue_id, pk)
        if attachment is None:
            return Response(
                {"error": "Issue attachment not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        if not can_read_issue(request.user, attachment.issue):
            return Response(
                {"error": "You are not allowed to view this issue"},
                status=status.HTTP_403_FORBIDDEN,
            )

        decision = resolve_preview_mapping(
            user=request.user,
            attachment=attachment,
            slug=slug,
            project_id=project_id,
        )
        if decision.state == "not_configured":
            return Response(
                {
                    "error": "Preview is not configured.",
                    "code": decision.code,
                    "preview_status": decision.state,
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        if decision.state == "invalid":
            return Response(
                {
                    "error": "Preview mapping is invalid.",
                    "code": decision.code,
                    "preview_status": decision.state,
                },
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        if decision.state == "unavailable":
            return Response(
                {
                    "error": "Preview target is no longer available.",
                    "code": decision.code,
                    "preview_status": decision.state,
                },
                status=status.HTTP_410_GONE,
            )
        if decision.state == "forbidden":
            message = (
                "Preview target is not available to project members."
                if decision.reason == "target_not_public"
                else "Preview target is not available to this user."
            )
            return Response(
                {
                    "error": message,
                    "code": decision.code,
                    "preview_status": decision.state,
                },
                status=status.HTTP_403_FORBIDDEN,
            )
        return self._ready_response(decision.page_id)

    @allow_permission([ROLE.ADMIN])
    def patch(self, request, slug, project_id, issue_id, pk):
        serializer = IssueAttachmentPreviewSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {
                    "error": "Preview mapping is invalid.",
                    "code": "preview_mapping_invalid",
                    "preview_status": "invalid",
                    "details": serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        decision = set_preview_mapping(
            user=request.user,
            slug=slug,
            project_id=project_id,
            issue_id=issue_id,
            asset_id=pk,
            page_id=serializer.validated_data["preview_page_id"],
        )
        if decision.state == "not_found":
            return Response(
                {"error": "Issue attachment not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        if decision.state == "target_invalid":
            return Response(
                {
                    "error": "Preview page must be an active public page in the same project.",
                    "code": decision.code,
                    "preview_status": "invalid",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        if decision.state == "attributes_invalid":
            return Response(
                {
                    "error": "Attachment attributes are invalid.",
                    "code": decision.code,
                    "preview_status": "invalid",
                },
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        return self._ready_response(decision.page_id)

    @allow_permission([ROLE.ADMIN])
    def delete(self, request, slug, project_id, issue_id, pk):
        decision = clear_preview_mapping(
            slug=slug,
            project_id=project_id,
            issue_id=issue_id,
            asset_id=pk,
        )
        if decision.state == "not_found":
            return Response(
                {"error": "Issue attachment not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        if decision.state == "attributes_invalid":
            return Response(
                {
                    "error": "Attachment attributes are invalid.",
                    "code": decision.code,
                    "preview_status": "invalid",
                },
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        return Response(status=status.HTTP_204_NO_CONTENT)


class IssueAttachmentInlineEndpoint(BaseAPIView):
    """Stream one authorized JPEG/PNG attachment without a public storage URL."""

    model = FileAsset
    _MAGIC = {
        "image/jpeg": lambda prefix: prefix.startswith(b"\xff\xd8\xff"),
        "image/png": lambda prefix: prefix.startswith(b"\x89PNG\r\n\x1a\n"),
    }

    @allow_permission([ROLE.ADMIN, ROLE.MEMBER, ROLE.GUEST])
    def get(self, request, slug, project_id, issue_id, pk):
        attachment = get_preview_attachment(slug, project_id, issue_id, pk)
        if attachment is None:
            return Response(
                {"error": "Issue attachment not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        if not can_read_issue(request.user, attachment.issue):
            return Response(
                {"error": "You are not allowed to view this issue"},
                status=status.HTTP_403_FORBIDDEN,
            )

        attributes = attachment.attributes
        if not isinstance(attributes, dict):
            return Response(
                {"error": "Attachment metadata is invalid."},
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        content_type = attributes.get("type")
        if content_type not in self._MAGIC:
            return Response(
                {"error": "Inline preview only supports JPEG and PNG images."},
                status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            )

        storage = S3Storage()
        try:
            source = storage.s3_client.get_object(
                Bucket=storage.aws_storage_bucket_name,
                Key=attachment.asset.name,
            )
        except (BotoCoreError, ClientError):
            return Response(
                {"error": "Attachment content is unavailable."},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        body = source.get("Body")
        content_length = source.get("ContentLength")
        stored_type = source.get("ContentType")
        if (
            body is None
            or not isinstance(content_length, int)
            or content_length < 1
            or content_length > settings.FILE_SIZE_LIMIT
            or attachment.size > settings.FILE_SIZE_LIMIT
        ):
            if body is not None:
                body.close()
            return Response(
                {"error": "Attachment size is invalid for inline preview."},
                status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )
        if stored_type and stored_type != content_type:
            body.close()
            return Response(
                {"error": "Attachment content type does not match its metadata."},
                status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            )

        try:
            prefix = body.read(8)
        except Exception:
            body.close()
            return Response(
                {"error": "Attachment content is unavailable."},
                status=status.HTTP_502_BAD_GATEWAY,
            )
        if not self._MAGIC[content_type](prefix):
            body.close()
            return Response(
                {"error": "Attachment content does not match its image type."},
                status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            )

        def stream_body():
            try:
                yield prefix
                for chunk in body.iter_chunks(chunk_size=64 * 1024):
                    if chunk:
                        yield chunk
            finally:
                body.close()

        response = StreamingHttpResponse(stream_body(), content_type=content_type)
        response["Content-Length"] = str(content_length)
        filename = quote(str(attributes.get("name") or attachment.id))
        response["Content-Disposition"] = f"inline; filename*=UTF-8''{filename}"
        response["X-Content-Type-Options"] = "nosniff"
        response["Cache-Control"] = "private, no-store"
        return response
