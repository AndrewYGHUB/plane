# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Contracts for API-key attachment preview mapping and safe Page import."""

import base64
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from botocore.exceptions import ConnectionClosedError, EndpointConnectionError
from django.db import close_old_connections, connection
from django.test import override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from plane.db.models import (
    APIToken,
    DeployBoard,
    FileAsset,
    Issue,
    Page,
    Project,
    ProjectMember,
    ProjectPage,
    User,
    WorkspaceMember,
)
from plane.utils.attachment_preview import (
    PREVIEW_PAGE_EXTERNAL_SOURCE,
    get_preview_attachment,
    preview_page_access_decision,
)
from plane.app.serializers.asset import (
    merge_attributes_preserving_controlled_preview,
)


class FakeBody:
    def __init__(self, data):
        self.data = data
        self.offset = 0
        self.closed = False

    def read(self, amount=None):
        if amount is None:
            amount = len(self.data) - self.offset
        result = self.data[self.offset : self.offset + amount]
        self.offset += len(result)
        return result

    def iter_chunks(self, chunk_size=64 * 1024):
        while self.offset < len(self.data):
            yield self.read(chunk_size)

    def close(self):
        self.closed = True


class RaisingBody(FakeBody):
    def read(self, amount=None):
        raise OSError("simulated object read failure")


def _api_client(user):
    token = APIToken.objects.create(user=user, label="preview-contract", token=uuid4().hex)
    client = APIClient()
    client.credentials(HTTP_X_API_KEY=token.token)
    return client


def _user(workspace, project, role):
    unique = uuid4().hex[:8]
    user = User.objects.create(email=f"role-{unique}@plane.so", username=f"role_{unique}")
    WorkspaceMember.objects.create(workspace=workspace, member=user, role=role)
    ProjectMember.objects.create(workspace=workspace, project=project, member=user, role=role)
    return user


def _preview_url(workspace, project, issue, attachment):
    return (
        f"/api/v1/workspaces/{workspace.slug}/projects/{project.id}/work-items/"
        f"{issue.id}/attachments/{attachment.id}/preview/"
    )


def _import_url(workspace, project, issue, attachment):
    return f"{_preview_url(workspace, project, issue, attachment)[:-8]}preview-page/"


def _app_inline_url(workspace, project, issue, attachment):
    return (
        f"/api/assets/v2/workspaces/{workspace.slug}/projects/{project.id}/issues/"
        f"{issue.id}/attachments/{attachment.id}/inline/"
    )


def _page_url(workspace, project, page):
    return f"/api/workspaces/{workspace.slug}/projects/{project.id}/pages/{page.id}/"


def _page_list_url(workspace, project):
    return f"/api/workspaces/{workspace.slug}/projects/{project.id}/pages/"


def _page_summary_url(workspace, project):
    return f"/api/workspaces/{workspace.slug}/projects/{project.id}/pages-summary/"


def _page_description_url(workspace, project, page):
    return f"{_page_url(workspace, project, page)}description/"


def _page_versions_url(workspace, project, page):
    return f"{_page_url(workspace, project, page)}versions/"


def _page_duplicate_url(workspace, project, page):
    return f"{_page_url(workspace, project, page)}duplicate/"


def _generic_asset_patch_url(kind, workspace, project, attachment, deploy_board):
    if kind == "workspace":
        return f"/api/assets/v2/workspaces/{workspace.slug}/{attachment.id}/"
    if kind == "project":
        return (
            f"/api/assets/v2/workspaces/{workspace.slug}/projects/"
            f"{project.id}/{attachment.id}/"
        )
    return f"/api/public/assets/v2/anchor/{deploy_board.anchor}/{attachment.id}/"


def _live_success():
    return Mock(
        status_code=200,
        json=lambda: {
            "description_json": {"type": "doc", "content": []},
            "description_binary": base64.b64encode(b"\x01\x02\x03\x04").decode(),
        },
    )


@pytest.fixture
def preview_api_context(db, workspace, create_user):
    project = Project.objects.create(
        name="API preview",
        identifier=f"PA{uuid4().hex[:6].upper()}",
        workspace=workspace,
        created_by=create_user,
    )
    ProjectMember.objects.create(
        workspace=workspace,
        project=project,
        member=create_user,
        role=20,
    )
    issue = Issue.objects.create(
        name="Attachment source",
        sequence_id=1,
        workspace=workspace,
        project=project,
        created_by=create_user,
    )
    attachment = FileAsset.objects.create(
        attributes={"name": "evidence.txt", "type": "text/plain", "size": 12},
        asset=f"{workspace.id}/evidence.txt",
        size=12,
        workspace=workspace,
        project=project,
        issue=issue,
        created_by=create_user,
        entity_type=FileAsset.EntityTypeContext.ISSUE_ATTACHMENT,
        is_uploaded=True,
        storage_metadata={"size": 12},
    )
    return project, issue, attachment


@pytest.mark.contract
class TestIssueAttachmentPreviewAPI:
    @pytest.mark.django_db
    def test_api_admin_maps_reads_and_clears_but_member_cannot_write(
        self, api_key_client, workspace, create_user, preview_api_context
    ):
        project, issue, attachment = preview_api_context
        page = Page.objects.create(
            workspace=workspace,
            owned_by=create_user,
            access=Page.PUBLIC_ACCESS,
            name="Existing page",
        )
        ProjectPage.objects.create(workspace=workspace, project=project, page=page)
        regular_page_session = APIClient()
        regular_page_session.force_authenticate(user=create_user)
        regular_page_details = regular_page_session.get(_page_url(workspace, project, page))
        assert regular_page_details.status_code == status.HTTP_200_OK
        assert regular_page_details.json()["attachment_preview_read_only"] is False
        url = _preview_url(workspace, project, issue, attachment)

        mapped = api_key_client.patch(
            url,
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)},
            format="json",
        )
        assert mapped.status_code == status.HTTP_200_OK
        assert api_key_client.get(url).json() == mapped.json()

        member = _user(workspace, project, 15)
        denied = _api_client(member).delete(url)
        assert denied.status_code == status.HTTP_403_FORBIDDEN
        assert api_key_client.delete(url).status_code == status.HTTP_204_NO_CONTENT
        attachment.refresh_from_db()
        assert "preview_page_id" not in attachment.attributes

    @pytest.mark.django_db
    def test_api_restricted_guest_cannot_resolve_own_issue_preview_to_foreign_owned_page(
        self, workspace, create_user, preview_api_context
    ):
        project, _, attachment = preview_api_context
        guest = _user(workspace, project, 5)
        own_issue = Issue(
            name="Guest-owned attachment",
            sequence_id=2,
            workspace=workspace,
            project=project,
            created_by=guest,
        )
        own_issue.save(disable_auto_set_user=True)
        attachment.issue = own_issue
        attachment.save(update_fields=["issue", "updated_at"])
        page = Page.objects.create(
            workspace=workspace,
            owned_by=create_user,
            access=Page.PUBLIC_ACCESS,
            name="Another user's public page",
        )
        ProjectPage.objects.create(workspace=workspace, project=project, page=page)
        attachment.attributes.update(
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)}
        )
        attachment.save(update_fields=["attributes", "updated_at"])

        response = _api_client(guest).get(
            _preview_url(workspace, project, own_issue, attachment)
        )
        guest_session = APIClient()
        guest_session.force_authenticate(user=guest)
        page_response = guest_session.get(_page_url(workspace, project, page))

        assert page.owned_by_id != guest.id
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["code"] == "preview_target_forbidden"
        assert response.json()["preview_status"] == "forbidden"
        assert page_response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_workspace_admin_project_member_fallback_can_map(
        self, workspace, create_user, preview_api_context
    ):
        project, issue, attachment = preview_api_context
        project_admin_fallback = _user(workspace, project, 5)
        WorkspaceMember.objects.filter(workspace=workspace, member=project_admin_fallback).update(role=20)
        page = Page.objects.create(
            workspace=workspace,
            owned_by=create_user,
            access=Page.PUBLIC_ACCESS,
            name="Fallback page",
        )
        ProjectPage.objects.create(workspace=workspace, project=project, page=page)

        response = _api_client(project_admin_fallback).patch(
            _preview_url(workspace, project, issue, attachment),
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_workspace_admin_project_guest_lists_ordinary_public_page(
        self, workspace, create_user, preview_api_context
    ):
        project, _, _ = preview_api_context
        workspace_admin = _user(workspace, project, 5)
        WorkspaceMember.objects.filter(
            workspace=workspace,
            member=workspace_admin,
        ).update(role=20)
        public_page = Page.objects.create(
            workspace=workspace,
            owned_by=create_user,
            access=Page.PUBLIC_ACCESS,
            name="Workspace admin visible page",
        )
        ProjectPage.objects.create(
            workspace=workspace,
            project=project,
            page=public_page,
        )
        client = APIClient()
        client.force_authenticate(user=workspace_admin)

        listed = client.get(_page_list_url(workspace, project))

        assert project.guest_view_all_features is False
        assert ProjectMember.objects.filter(
            project=project,
            member=workspace_admin,
            role=5,
            is_active=True,
        ).exists()
        assert WorkspaceMember.objects.filter(
            workspace=workspace,
            member=workspace_admin,
            role=20,
            is_active=True,
        ).exists()
        assert listed.status_code == status.HTTP_200_OK
        assert str(public_page.id) in {row["id"] for row in listed.json()}

    @pytest.mark.django_db
    def test_restricted_guest_summary_matches_source_readable_derived_page_list(
        self, workspace, create_user, preview_api_context
    ):
        project, _, unrelated_attachment = preview_api_context
        guest = _user(workspace, project, 5)
        own_issue = Issue(
            name="Summary-readable source",
            sequence_id=2,
            workspace=workspace,
            project=project,
            created_by=guest,
        )
        own_issue.save(disable_auto_set_user=True)
        own_attachment = FileAsset(
            attributes={"name": "summary-source.txt", "type": "text/plain", "size": 12},
            asset=f"{workspace.id}/summary-source.txt",
            size=12,
            workspace=workspace,
            project=project,
            issue=own_issue,
            created_by=guest,
            entity_type=FileAsset.EntityTypeContext.ISSUE_ATTACHMENT,
            is_uploaded=True,
            storage_metadata={"size": 12},
        )
        own_attachment.save(disable_auto_set_user=True)
        allowed_preview = Page.objects.create(
            workspace=workspace,
            owned_by=create_user,
            access=Page.PUBLIC_ACCESS,
            name="Summary-visible derived page",
            external_source=PREVIEW_PAGE_EXTERNAL_SOURCE,
            external_id=str(own_attachment.id),
        )
        denied_preview = Page.objects.create(
            workspace=workspace,
            owned_by=create_user,
            access=Page.PUBLIC_ACCESS,
            name="Summary-hidden derived page",
            external_source=PREVIEW_PAGE_EXTERNAL_SOURCE,
            external_id=str(unrelated_attachment.id),
        )
        for page in (allowed_preview, denied_preview):
            ProjectPage.objects.create(workspace=workspace, project=project, page=page)
        client = APIClient()
        client.force_authenticate(user=guest)

        listed = client.get(_page_list_url(workspace, project))
        summary = client.get(_page_summary_url(workspace, project))
        listed_ids = {row["id"] for row in listed.json()}

        assert listed.status_code == status.HTTP_200_OK
        assert summary.status_code == status.HTTP_200_OK
        assert str(allowed_preview.id) in listed_ids
        assert str(denied_preview.id) not in listed_ids
        assert summary.json() == {
            "public_pages": len(listed_ids),
            "private_pages": 0,
            "archived_pages": 0,
        }

    @pytest.mark.django_db
    def test_space_generic_preview_mutation_rejects_before_metadata_side_effects(
        self, workspace, create_user, preview_api_context
    ):
        project, _, attachment = preview_api_context
        attachment.is_uploaded = False
        attachment.storage_metadata = {}
        attachment.save(
            update_fields=["is_uploaded", "storage_metadata", "updated_at"]
        )
        deploy_board = DeployBoard.objects.create(
            workspace=workspace,
            project=project,
            entity_name="project",
            entity_identifier=project.id,
        )
        client = APIClient()
        client.force_authenticate(user=create_user)

        with patch(
            "plane.space.views.asset.get_asset_object_metadata.delay"
        ) as metadata_task:
            response = client.patch(
                _generic_asset_patch_url(
                    "space", workspace, project, attachment, deploy_board
                ),
                {
                    "attributes": {
                        "name": "must-not-mutate.txt",
                        "preview_kind": "plane_page",
                        "preview_page_id": str(uuid4()),
                    }
                },
                format="json",
            )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["code"] == "preview_mapping_requires_admin_endpoint"
        metadata_task.assert_not_called()
        attachment.refresh_from_db()
        assert attachment.is_uploaded is False
        assert attachment.storage_metadata == {}
        assert attachment.attributes["name"] == "evidence.txt"

    @pytest.mark.django_db(transaction=True)
    @pytest.mark.parametrize("generic_endpoint", ["workspace", "project", "space"])
    def test_generic_metadata_patch_serializes_before_controlled_mapping_set(
        self,
        workspace,
        create_user,
        preview_api_context,
        generic_endpoint,
    ):
        project, issue, attachment = preview_api_context
        page = Page.objects.create(
            workspace=workspace,
            owned_by=create_user,
            access=Page.PUBLIC_ACCESS,
            name="Concurrent preview target",
        )
        ProjectPage.objects.create(workspace=workspace, project=project, page=page)
        deploy_board = DeployBoard.objects.create(
            workspace=workspace,
            project=project,
            entity_name="project",
            entity_identifier=project.id,
        )
        generic_locked = Event()
        release_generic = Event()
        controlled_started = Event()
        generic_url = _generic_asset_patch_url(
            generic_endpoint, workspace, project, attachment, deploy_board
        )
        merge_path = (
            "plane.space.views.asset.merge_attributes_preserving_controlled_preview"
            if generic_endpoint == "space"
            else "plane.app.views.asset.v2.merge_attributes_preserving_controlled_preview"
        )

        def blocking_merge(current, requested):
            generic_locked.set()
            assert release_generic.wait(10), "generic metadata PATCH was not released"
            return merge_attributes_preserving_controlled_preview(current, requested)

        def observed_get_preview_attachment(*args, **kwargs):
            if kwargs.get("for_update"):
                controlled_started.set()
            return get_preview_attachment(*args, **kwargs)

        def generic_patch():
            close_old_connections()
            try:
                client = APIClient()
                client.force_authenticate(user=create_user)
                return client.patch(
                    generic_url,
                    {"attributes": {"name": "metadata-after-lock.txt", "type": "text/plain"}},
                    format="json",
                )
            finally:
                close_old_connections()

        def controlled_set():
            close_old_connections()
            try:
                return _api_client(create_user).patch(
                    _preview_url(workspace, project, issue, attachment),
                    {"preview_kind": "plane_page", "preview_page_id": str(page.id)},
                    format="json",
                )
            finally:
                close_old_connections()

        with patch(merge_path, side_effect=blocking_merge), patch(
            "plane.utils.attachment_preview.get_preview_attachment",
            side_effect=observed_get_preview_attachment,
        ):
            with ThreadPoolExecutor(max_workers=2) as executor:
                generic_future = executor.submit(generic_patch)
                assert generic_locked.wait(10), "generic PATCH never held the attachment row"
                controlled_future = executor.submit(controlled_set)
                assert controlled_started.wait(10), "controlled mapping set never reached its row lock"
                assert controlled_future.done() is False
                release_generic.set()
                generic_response = generic_future.result(timeout=10)
                controlled_response = controlled_future.result(timeout=10)

        assert generic_response.status_code == status.HTTP_204_NO_CONTENT
        assert controlled_response.status_code == status.HTTP_200_OK
        attachment.refresh_from_db()
        assert attachment.attributes["name"] == "metadata-after-lock.txt"
        assert attachment.attributes["preview_kind"] == "plane_page"
        assert attachment.attributes["preview_page_id"] == str(page.id)

    @pytest.mark.django_db(transaction=True)
    @pytest.mark.parametrize("generic_endpoint", ["workspace", "project", "space"])
    def test_generic_metadata_patch_serializes_before_controlled_mapping_clear(
        self,
        workspace,
        create_user,
        preview_api_context,
        generic_endpoint,
    ):
        project, issue, attachment = preview_api_context
        attachment.attributes = {
            **attachment.attributes,
            "preview_kind": "plane_page",
            "preview_page_id": str(uuid4()),
        }
        attachment.save(update_fields=["attributes", "updated_at"])
        deploy_board = DeployBoard.objects.create(
            workspace=workspace,
            project=project,
            entity_name="project",
            entity_identifier=project.id,
        )
        generic_locked = Event()
        release_generic = Event()
        controlled_started = Event()
        generic_url = _generic_asset_patch_url(
            generic_endpoint, workspace, project, attachment, deploy_board
        )
        merge_path = (
            "plane.space.views.asset.merge_attributes_preserving_controlled_preview"
            if generic_endpoint == "space"
            else "plane.app.views.asset.v2.merge_attributes_preserving_controlled_preview"
        )

        def blocking_merge(current, requested):
            generic_locked.set()
            assert release_generic.wait(10), "generic metadata PATCH was not released"
            return merge_attributes_preserving_controlled_preview(current, requested)

        def observed_get_preview_attachment(*args, **kwargs):
            if kwargs.get("for_update"):
                controlled_started.set()
            return get_preview_attachment(*args, **kwargs)

        def generic_patch():
            close_old_connections()
            try:
                client = APIClient()
                client.force_authenticate(user=create_user)
                return client.patch(
                    generic_url,
                    {"attributes": {"name": "metadata-before-clear.txt", "type": "text/plain"}},
                    format="json",
                )
            finally:
                close_old_connections()

        def controlled_clear():
            close_old_connections()
            try:
                return _api_client(create_user).delete(
                    _preview_url(workspace, project, issue, attachment)
                )
            finally:
                close_old_connections()

        with patch(merge_path, side_effect=blocking_merge), patch(
            "plane.utils.attachment_preview.get_preview_attachment",
            side_effect=observed_get_preview_attachment,
        ):
            with ThreadPoolExecutor(max_workers=2) as executor:
                generic_future = executor.submit(generic_patch)
                assert generic_locked.wait(10), "generic PATCH never held the attachment row"
                controlled_future = executor.submit(controlled_clear)
                assert controlled_started.wait(10), "controlled mapping clear never reached its row lock"
                assert controlled_future.done() is False
                release_generic.set()
                generic_response = generic_future.result(timeout=10)
                controlled_response = controlled_future.result(timeout=10)

        assert generic_response.status_code == status.HTTP_204_NO_CONTENT
        assert controlled_response.status_code == status.HTTP_204_NO_CONTENT
        attachment.refresh_from_db()
        assert attachment.attributes["name"] == "metadata-before-clear.txt"
        assert "preview_kind" not in attachment.attributes
        assert "preview_page_id" not in attachment.attributes

    @pytest.mark.django_db
    @override_settings(LIVE_URL="http://plane-live.internal/live/")
    def test_text_import_is_escaped_atomic_and_idempotent(
        self, api_key_client, workspace, preview_api_context
    ):
        project, issue, attachment = preview_api_context
        original_asset = attachment.asset.name
        source = b"<script>alert(1)</script>\nplain evidence"
        storage = Mock()
        storage.aws_storage_bucket_name = "uploads"
        storage.s3_client.get_object.return_value = {
            "Body": FakeBody(source),
            "ContentLength": len(source),
            "ContentType": "text/plain",
        }
        url = _import_url(workspace, project, issue, attachment)

        with patch("plane.api.views.issue_attachment_preview.S3Storage", return_value=storage), patch(
            "plane.api.views.issue_attachment_preview.requests.post", return_value=_live_success()
        ) as convert:
            created = api_key_client.post(url)

        assert created.status_code == status.HTTP_201_CREATED
        page = Page.objects.get(id=created.json()["preview_page_id"])
        assert page.external_source == "issue_attachment_preview"
        assert page.external_id == str(attachment.id)
        assert "&lt;script&gt;" in page.description_html
        assert "<script>" not in page.description_html
        assert page.access == Page.PUBLIC_ACCESS
        assert page.is_locked is True
        convert.assert_called_once()
        attachment.refresh_from_db()
        assert attachment.asset.name == original_asset

        admin_session = APIClient()
        admin_session.force_authenticate(user=page.owned_by)
        page_details = admin_session.get(_page_url(workspace, project, page))
        assert page_details.status_code == status.HTTP_200_OK
        assert page_details.json()["attachment_preview_read_only"] is True
        assert page_details.json()["is_locked"] is True
        assert (
            admin_session.patch(
                _page_url(workspace, project, page),
                {"name": "derived pages stay immutable"},
                format="json",
            ).status_code
            == status.HTTP_403_FORBIDDEN
        )

        repeated = api_key_client.post(url)
        assert repeated.status_code == status.HTTP_200_OK
        assert repeated.json()["created"] is False
        assert Page.objects.filter(
            external_source="issue_attachment_preview", external_id=str(attachment.id)
        ).count() == 1

    @pytest.mark.django_db
    @pytest.mark.parametrize(
        ("response_overrides", "expected_code"),
        [
            ({"ContentLength": "12"}, "preview_source_too_large"),
            ({"ContentType": "application/json"}, "preview_source_type_mismatch"),
        ],
    )
    def test_text_import_closes_body_when_object_metadata_is_rejected(
        self,
        api_key_client,
        preview_api_context,
        response_overrides,
        expected_code,
    ):
        project, issue, attachment = preview_api_context
        body = FakeBody(b"safe evidence")
        response = {
            "Body": body,
            "ContentLength": len(body.data),
            "ContentType": "text/plain",
        }
        response.update(response_overrides)
        storage = Mock()
        storage.aws_storage_bucket_name = "uploads"
        storage.s3_client.get_object.return_value = response

        with patch("plane.api.views.issue_attachment_preview.S3Storage", return_value=storage):
            rejected = api_key_client.post(_import_url(project.workspace, project, issue, attachment))

        assert rejected.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert rejected.json()["code"] == expected_code
        assert body.closed is True

    @pytest.mark.django_db
    def test_text_import_closes_body_when_object_read_fails(
        self, api_key_client, preview_api_context
    ):
        project, issue, attachment = preview_api_context
        body = RaisingBody(b"safe evidence")
        storage = Mock()
        storage.aws_storage_bucket_name = "uploads"
        storage.s3_client.get_object.return_value = {
            "Body": body,
            "ContentLength": len(body.data),
            "ContentType": "text/plain",
        }

        with patch("plane.api.views.issue_attachment_preview.S3Storage", return_value=storage):
            failed = api_key_client.post(_import_url(project.workspace, project, issue, attachment))

        assert failed.status_code == status.HTTP_502_BAD_GATEWAY
        assert failed.json()["code"] == "preview_source_unavailable"
        assert body.closed is True

    @pytest.mark.django_db
    @override_settings(LIVE_URL="http://plane-live.internal/live/")
    def test_concurrent_mapping_wins_after_external_work_outside_transaction(
        self, api_key_client, workspace, create_user, preview_api_context
    ):
        project, issue, attachment = preview_api_context
        mapped_page = Page.objects.create(
            workspace=workspace,
            owned_by=create_user,
            access=Page.PUBLIC_ACCESS,
            name="Concurrent mapping",
        )
        ProjectPage.objects.create(workspace=workspace, project=project, page=mapped_page)
        source = b"safe evidence"
        body = FakeBody(source)
        storage = Mock()
        storage.aws_storage_bucket_name = "uploads"
        baseline_atomic_depth = len(connection.atomic_blocks)

        def get_object(**_kwargs):
            assert len(connection.atomic_blocks) == baseline_atomic_depth
            return {
                "Body": body,
                "ContentLength": len(source),
                "ContentType": "text/plain",
            }

        def map_during_conversion(*_args, **_kwargs):
            assert len(connection.atomic_blocks) == baseline_atomic_depth
            attributes = dict(attachment.attributes)
            attributes.update(
                {"preview_kind": "plane_page", "preview_page_id": str(mapped_page.id)}
            )
            FileAsset.objects.filter(id=attachment.id).update(attributes=attributes)
            return _live_success()

        storage.s3_client.get_object.side_effect = get_object
        with patch("plane.api.views.issue_attachment_preview.S3Storage", return_value=storage), patch(
            "plane.api.views.issue_attachment_preview.requests.post",
            side_effect=map_during_conversion,
        ):
            response = api_key_client.post(_import_url(workspace, project, issue, attachment))

        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {
            "preview_status": "ready",
            "preview_kind": "plane_page",
            "preview_page_id": str(mapped_page.id),
            "created": False,
        }
        assert not Page.objects.filter(
            external_source="issue_attachment_preview", external_id=str(attachment.id)
        ).exists()

    @pytest.mark.django_db
    @override_settings(LIVE_URL="http://plane-live.internal/live/")
    def test_source_identity_change_during_conversion_aborts_import(
        self, api_key_client, workspace, preview_api_context
    ):
        project, issue, attachment = preview_api_context
        source = b"safe evidence"
        storage = Mock()
        storage.aws_storage_bucket_name = "uploads"
        storage.s3_client.get_object.return_value = {
            "Body": FakeBody(source),
            "ContentLength": len(source),
            "ContentType": "text/plain",
        }
        baseline_atomic_depth = len(connection.atomic_blocks)

        def replace_source(*_args, **_kwargs):
            assert len(connection.atomic_blocks) == baseline_atomic_depth
            FileAsset.objects.filter(id=attachment.id).update(
                asset=f"{workspace.id}/replacement.txt"
            )
            return _live_success()

        with patch("plane.api.views.issue_attachment_preview.S3Storage", return_value=storage), patch(
            "plane.api.views.issue_attachment_preview.requests.post", side_effect=replace_source
        ):
            response = api_key_client.post(_import_url(workspace, project, issue, attachment))

        assert response.status_code == status.HTTP_409_CONFLICT
        assert response.json()["code"] == "preview_source_changed"
        assert not Page.objects.filter(
            external_source="issue_attachment_preview", external_id=str(attachment.id)
        ).exists()

    @pytest.mark.django_db
    @override_settings(LIVE_URL="http://plane-live.internal/live/")
    def test_sensitive_text_and_live_failure_roll_back_without_mapping(
        self, api_key_client, workspace, preview_api_context
    ):
        project, issue, attachment = preview_api_context
        url = _import_url(workspace, project, issue, attachment)
        storage = Mock()
        storage.aws_storage_bucket_name = "uploads"
        secret = b"-----BEGIN PRIVATE KEY-----\nnot-for-a-page"
        storage.s3_client.get_object.return_value = {
            "Body": FakeBody(secret),
            "ContentLength": len(secret),
            "ContentType": "text/plain",
        }
        with patch("plane.api.views.issue_attachment_preview.S3Storage", return_value=storage):
            rejected = api_key_client.post(url)
        assert rejected.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert rejected.json()["code"] == "contains_sensitive_data"
        assert not Page.objects.filter(external_id=str(attachment.id)).exists()

        plain = b"safe text"
        storage.s3_client.get_object.return_value = {
            "Body": FakeBody(plain),
            "ContentLength": len(plain),
            "ContentType": "text/plain",
        }
        with patch("plane.api.views.issue_attachment_preview.S3Storage", return_value=storage), patch(
            "plane.api.views.issue_attachment_preview.requests.post",
            return_value=Mock(status_code=503),
        ):
            failed = api_key_client.post(url)
        assert failed.status_code == status.HTTP_502_BAD_GATEWAY
        assert failed.json()["code"] == "preview_conversion_failed"
        assert not Page.objects.filter(external_id=str(attachment.id)).exists()
        attachment.refresh_from_db()
        assert "preview_page_id" not in attachment.attributes

    @pytest.mark.django_db
    @override_settings(LIVE_URL="http://plane-live.internal/live/")
    def test_image_import_uses_authenticated_inline_endpoint_and_validates_magic(
        self, api_key_client, workspace, preview_api_context
    ):
        project, issue, attachment = preview_api_context
        attachment.attributes = {"name": "evidence.png", "type": "image/png", "size": 16}
        attachment.size = 16
        attachment.save(update_fields=["attributes", "size", "updated_at"])
        storage = Mock()
        storage.aws_storage_bucket_name = "uploads"
        storage.s3_client.head_object.return_value = {
            "ContentLength": 16,
            "ContentType": "image/png",
        }
        storage.s3_client.get_object.return_value = {
            "Body": FakeBody(b"\x89PNG\r\n\x1a\n"),
        }
        with patch("plane.api.views.issue_attachment_preview.S3Storage", return_value=storage), patch(
            "plane.api.views.issue_attachment_preview.requests.post", return_value=_live_success()
        ) as convert:
            response = api_key_client.post(_import_url(workspace, project, issue, attachment))
        assert response.status_code == status.HTTP_201_CREATED
        submitted_html = convert.call_args.kwargs["json"]["description_html"]
        assert _app_inline_url(workspace, project, issue, attachment) in submitted_html
        assert 'status="uploaded"' in submitted_html
        assert 'width="100%"' in submitted_html
        assert 'height="auto"' in submitted_html
        assert 'alignment="center"' in submitted_html
        assert " alt=" not in submitted_html
        assert "asset_url" not in submitted_html

        # The endpoint persisted the mapping through a separate ORM instance.
        # Refresh this fixture before clearing it for the negative-control import.
        attachment.refresh_from_db()
        attachment.attributes.pop("preview_kind")
        attachment.attributes.pop("preview_page_id")
        attachment.save(update_fields=["attributes", "updated_at"])
        Page.objects.filter(external_id=str(attachment.id)).delete(soft=False)
        storage.s3_client.get_object.return_value = {"Body": FakeBody(b"not-png!")}
        with patch("plane.api.views.issue_attachment_preview.S3Storage", return_value=storage):
            rejected = api_key_client.post(_import_url(workspace, project, issue, attachment))
        assert rejected.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert rejected.json()["code"] == "preview_source_type_mismatch"

    @pytest.mark.django_db
    @override_settings(LIVE_URL="http://plane-live.internal/live/")
    def test_derived_page_keeps_issue_acl_after_mapping_clear_and_source_deletion(
        self, api_key_client, workspace, create_user, preview_api_context
    ):
        project, issue, attachment = preview_api_context
        source = b"visible only through source issue ACL"
        storage = Mock()
        storage.aws_storage_bucket_name = "uploads"
        storage.s3_client.get_object.return_value = {
            "Body": FakeBody(source),
            "ContentLength": len(source),
            "ContentType": "text/plain",
        }
        with patch("plane.api.views.issue_attachment_preview.S3Storage", return_value=storage), patch(
            "plane.api.views.issue_attachment_preview.requests.post", return_value=_live_success()
        ):
            created = api_key_client.post(_import_url(workspace, project, issue, attachment))
        page = Page.objects.get(id=created.json()["preview_page_id"])

        guest = _user(workspace, project, 5)
        guest_client = APIClient()
        guest_client.force_authenticate(user=guest)
        assert guest_client.get(_page_url(workspace, project, page)).status_code == status.HTTP_403_FORBIDDEN
        assert guest_client.get(_page_description_url(workspace, project, page)).status_code == status.HTTP_403_FORBIDDEN

        assert api_key_client.delete(_preview_url(workspace, project, issue, attachment)).status_code == 204
        assert guest_client.get(_page_url(workspace, project, page)).status_code == status.HTTP_403_FORBIDDEN

        Issue.all_objects.filter(id=issue.id).update(deleted_at=timezone.now())
        admin_session = APIClient()
        admin_session.force_authenticate(user=create_user)
        assert admin_session.get(_page_url(workspace, project, page)).status_code == status.HTTP_403_FORBIDDEN
        assert admin_session.get(_page_description_url(workspace, project, page)).status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    @override_settings(LIVE_URL="http://plane-live.internal/live/")
    def test_restricted_guest_can_open_derived_page_for_own_issue(
        self, api_key_client, workspace, create_user, preview_api_context
    ):
        project, _, attachment = preview_api_context
        guest = _user(workspace, project, 5)
        own_issue = Issue(
            name="Guest source",
            sequence_id=2,
            workspace=workspace,
            project=project,
            created_by=guest,
        )
        # APIClient requests leave CRUM's current user set for the request
        # lifecycle. Bypass BaseModel's audit auto-fill so this fixture tests
        # the intended Guest-owned Issue rather than whichever API identity ran
        # immediately before this setup step.
        own_issue.save(disable_auto_set_user=True)
        own_issue.refresh_from_db()
        assert own_issue.created_by_id == guest.id
        attachment.issue = own_issue
        attachment.save(update_fields=["issue", "updated_at"])
        source = b"guest-owned evidence"
        storage = Mock()
        storage.aws_storage_bucket_name = "uploads"
        storage.s3_client.get_object.return_value = {
            "Body": FakeBody(source),
            "ContentLength": len(source),
            "ContentType": "text/plain",
        }
        with patch("plane.api.views.issue_attachment_preview.S3Storage", return_value=storage), patch(
            "plane.api.views.issue_attachment_preview.requests.post", return_value=_live_success()
        ):
            created = api_key_client.post(_import_url(workspace, project, own_issue, attachment))
        page = Page.objects.get(id=created.json()["preview_page_id"])
        guest_session = APIClient()
        guest_session.force_authenticate(user=guest)
        assert preview_page_access_decision(guest, page, project.id) is True
        assert ProjectMember.objects.filter(
            workspace=workspace,
            project=project,
            member=guest,
            role=5,
            is_active=True,
        ).exists()
        page_response = guest_session.get(_page_url(workspace, project, page))
        assert page_response.status_code == status.HTTP_200_OK, page_response.json()
        assert guest_session.get(_page_description_url(workspace, project, page)).status_code == status.HTTP_200_OK
        assert guest_session.get(_page_versions_url(workspace, project, page)).status_code == status.HTTP_200_OK

        # Source ACL grants read-only access to the derived projection. It must
        # not grant Page mutation or duplication rights to the source viewer.
        assert (
            guest_session.patch(
                _page_url(workspace, project, page),
                {"name": "must not change"},
                format="json",
            ).status_code
            == status.HTTP_403_FORBIDDEN
        )
        assert (
            guest_session.patch(
                _page_description_url(workspace, project, page),
                {"description_html": "<p>must not change</p>"},
                format="json",
            ).status_code
            == status.HTTP_403_FORBIDDEN
        )
        assert (
            guest_session.post(_page_duplicate_url(workspace, project, page)).status_code
            == status.HTTP_403_FORBIDDEN
        )

    @pytest.mark.django_db
    def test_restricted_guest_page_list_hides_unrelated_derived_metadata(
        self, workspace, create_user, preview_api_context
    ):
        project, unrelated_issue, unrelated_attachment = preview_api_context
        guest = _user(workspace, project, 5)
        guest_issue = Issue(
            name="Guest-visible source",
            sequence_id=2,
            workspace=workspace,
            project=project,
            created_by=guest,
        )
        guest_issue.save(disable_auto_set_user=True)
        guest_attachment = FileAsset(
            attributes={"name": "guest-evidence.txt", "type": "text/plain", "size": 12},
            asset=f"{workspace.id}/guest-evidence.txt",
            size=12,
            workspace=workspace,
            project=project,
            issue=guest_issue,
            created_by=guest,
            entity_type=FileAsset.EntityTypeContext.ISSUE_ATTACHMENT,
            is_uploaded=True,
            storage_metadata={"size": 12},
        )
        guest_attachment.save(disable_auto_set_user=True)

        allowed_preview = Page.objects.create(
            workspace=workspace,
            owned_by=create_user,
            access=Page.PUBLIC_ACCESS,
            name="Guest source preview",
            external_source=PREVIEW_PAGE_EXTERNAL_SOURCE,
            external_id=str(guest_attachment.id),
        )
        denied_preview = Page.objects.create(
            workspace=workspace,
            owned_by=create_user,
            access=Page.PUBLIC_ACCESS,
            name="Unrelated source preview",
            external_source=PREVIEW_PAGE_EXTERNAL_SOURCE,
            external_id=str(unrelated_attachment.id),
        )
        ordinary_owned_page = Page.objects.create(
            workspace=workspace,
            owned_by=guest,
            access=Page.PUBLIC_ACCESS,
            name="Guest ordinary page",
        )
        for page in (allowed_preview, denied_preview, ordinary_owned_page):
            ProjectPage.objects.create(workspace=workspace, project=project, page=page)

        guest_session = APIClient()
        guest_session.force_authenticate(user=guest)
        listed = guest_session.get(_page_list_url(workspace, project))
        listed_ids = {row["id"] for row in listed.json()}

        assert project.guest_view_all_features is False
        assert unrelated_issue.created_by_id != guest.id
        assert listed.status_code == status.HTTP_200_OK
        assert str(allowed_preview.id) in listed_ids
        assert str(ordinary_owned_page.id) in listed_ids
        assert str(denied_preview.id) not in listed_ids
        assert (
            guest_session.get(_page_url(workspace, project, allowed_preview)).status_code
            == status.HTTP_200_OK
        )
        assert (
            guest_session.get(_page_url(workspace, project, denied_preview)).status_code
            == status.HTTP_403_FORBIDDEN
        )

    @pytest.mark.django_db
    def test_inline_image_checks_issue_acl_mime_size_and_magic(
        self, workspace, create_user, preview_api_context
    ):
        project, issue, attachment = preview_api_context
        attachment.attributes = {"name": "evidence.png", "type": "image/png", "size": 12}
        attachment.size = 12
        attachment.save(update_fields=["attributes", "size", "updated_at"])
        url = _app_inline_url(workspace, project, issue, attachment)
        guest = _user(workspace, project, 5)
        guest_client = APIClient()
        guest_client.force_authenticate(user=guest)
        assert guest_client.get(url).status_code == status.HTTP_403_FORBIDDEN

        admin_client = APIClient()
        admin_client.force_authenticate(user=create_user)
        image = b"\x89PNG\r\n\x1a\nrest"
        storage = Mock()
        storage.aws_storage_bucket_name = "uploads"
        storage.s3_client.get_object.return_value = {
            "Body": FakeBody(image),
            "ContentLength": len(image),
            "ContentType": "image/png",
        }
        with patch("plane.app.views.issue.attachment.S3Storage", return_value=storage):
            streamed = admin_client.get(url)
            assert streamed.status_code == status.HTTP_200_OK
            assert b"".join(streamed.streaming_content) == image
        assert streamed["Content-Disposition"].startswith("inline;")
        assert streamed["X-Content-Type-Options"] == "nosniff"

        storage.s3_client.get_object.return_value = {
            "Body": FakeBody(b"not-png-data"),
            "ContentLength": 12,
            "ContentType": "image/png",
        }
        with patch("plane.app.views.issue.attachment.S3Storage", return_value=storage):
            mismatch = admin_client.get(url)
        assert mismatch.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE

    @pytest.mark.django_db
    def test_inline_image_closes_body_when_magic_prefix_read_fails(
        self, workspace, create_user, preview_api_context
    ):
        project, issue, attachment = preview_api_context
        attachment.attributes = {"name": "evidence.png", "type": "image/png", "size": 12}
        attachment.size = 12
        attachment.save(update_fields=["attributes", "size", "updated_at"])
        body = RaisingBody(b"\x89PNG\r\n\x1a\nrest")
        storage = Mock()
        storage.aws_storage_bucket_name = "uploads"
        storage.s3_client.get_object.return_value = {
            "Body": body,
            "ContentLength": len(body.data),
            "ContentType": "image/png",
        }
        admin_client = APIClient()
        admin_client.force_authenticate(user=create_user)

        with patch("plane.app.views.issue.attachment.S3Storage", return_value=storage):
            response = admin_client.get(_app_inline_url(workspace, project, issue, attachment))

        assert response.status_code == status.HTTP_502_BAD_GATEWAY
        assert response.json() == {"error": "Attachment content is unavailable."}
        assert body.closed is True

    @pytest.mark.django_db
    @pytest.mark.parametrize(
        "storage_error",
        [
            EndpointConnectionError(endpoint_url="https://storage.internal"),
            ConnectionClosedError(endpoint_url="https://storage.internal"),
        ],
    )
    def test_inline_image_maps_storage_transport_failures_to_bad_gateway(
        self, workspace, create_user, preview_api_context, storage_error
    ):
        project, issue, attachment = preview_api_context
        attachment.attributes = {
            "name": "evidence.png",
            "type": "image/png",
            "size": 12,
        }
        attachment.size = 12
        attachment.save(update_fields=["attributes", "size", "updated_at"])
        storage = Mock()
        storage.aws_storage_bucket_name = "uploads"
        storage.s3_client.get_object.side_effect = storage_error
        admin_client = APIClient()
        admin_client.force_authenticate(user=create_user)

        with patch("plane.app.views.issue.attachment.S3Storage", return_value=storage):
            response = admin_client.get(
                _app_inline_url(workspace, project, issue, attachment)
            )

        assert response.status_code == status.HTTP_502_BAD_GATEWAY
        assert response.json() == {"error": "Attachment content is unavailable."}

    @pytest.mark.django_db
    def test_inline_image_does_not_map_programming_errors_to_storage_failure(
        self, workspace, create_user, preview_api_context
    ):
        project, issue, attachment = preview_api_context
        attachment.attributes = {
            "name": "evidence.png",
            "type": "image/png",
            "size": 12,
        }
        attachment.size = 12
        attachment.save(update_fields=["attributes", "size", "updated_at"])
        storage = Mock()
        storage.aws_storage_bucket_name = "uploads"
        storage.s3_client.get_object.side_effect = RuntimeError("programming defect")
        admin_client = APIClient()
        admin_client.force_authenticate(user=create_user)

        with patch("plane.app.views.issue.attachment.S3Storage", return_value=storage):
            response = admin_client.get(
                _app_inline_url(workspace, project, issue, attachment)
            )

        # BaseAPIView records uncaught programming errors and renders HTTP 500.
        # The inline handler must not misclassify them as storage transport 502s.
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert response.status_code != status.HTTP_502_BAD_GATEWAY
