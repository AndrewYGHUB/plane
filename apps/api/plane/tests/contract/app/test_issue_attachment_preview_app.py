# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Contract coverage for controlled issue-attachment Page previews."""

from uuid import uuid4

import pytest
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from plane.db.models import (
    FileAsset,
    Issue,
    Page,
    Project,
    ProjectMember,
    ProjectPage,
    User,
    WorkspaceMember,
)


def _preview_url(workspace, project, issue, attachment):
    return (
        f"/api/assets/v2/workspaces/{workspace.slug}/projects/{project.id}/"
        f"issues/{issue.id}/attachments/{attachment.id}/preview/"
    )


def _attachments_url(workspace, project, issue):
    return (
        f"/api/assets/v2/workspaces/{workspace.slug}/projects/{project.id}/"
        f"issues/{issue.id}/attachments/"
    )


def _attachment_download_url(workspace, project, issue, attachment):
    return (
        f"/api/assets/v2/workspaces/{workspace.slug}/projects/{project.id}/"
        f"issues/{issue.id}/attachments/{attachment.id}/"
    )


def _project_asset_url(workspace, project, attachment):
    return (
        f"/api/assets/v2/workspaces/{workspace.slug}/projects/{project.id}/"
        f"{attachment.id}/"
    )


def _page_url(workspace, project, page):
    return f"/api/workspaces/{workspace.slug}/projects/{project.id}/pages/{page.id}/"


def _create_uploaded_attachment(workspace, project, issue, created_by, name="evidence.pdf"):
    attachment = FileAsset(
        attributes={"name": name, "type": "application/pdf", "size": 128},
        asset=f"{workspace.id}/{uuid4().hex}-{name}",
        size=128,
        workspace=workspace,
        project=project,
        issue=issue,
        entity_type=FileAsset.EntityTypeContext.ISSUE_ATTACHMENT,
        is_uploaded=True,
        storage_metadata={"size": 128},
    )
    attachment.save(created_by_id=created_by.id)
    return attachment


def _create_guest(workspace, project):
    unique_id = uuid4().hex[:8]
    guest = User.objects.create(
        email=f"guest-{unique_id}@plane.so",
        username=f"guest_{unique_id}",
    )
    WorkspaceMember.objects.create(workspace=workspace, member=guest, role=5)
    ProjectMember.objects.create(
        workspace=workspace,
        project=project,
        member=guest,
        role=5,
    )
    client = APIClient()
    client.force_authenticate(user=guest)
    return guest, client


@pytest.fixture
def preview_context(db, workspace, create_user):
    project = Project.objects.create(
        name="Preview Project",
        identifier=f"PV{uuid4().hex[:6].upper()}",
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
        name="Preview attachment",
        sequence_id=1,
        workspace=workspace,
        project=project,
        created_by=create_user,
    )
    attachment = FileAsset.objects.create(
        attributes={"name": "evidence.pdf", "type": "application/pdf", "size": 128},
        asset=f"{workspace.id}/evidence.pdf",
        size=128,
        workspace=workspace,
        project=project,
        issue=issue,
        created_by=create_user,
        entity_type=FileAsset.EntityTypeContext.ISSUE_ATTACHMENT,
        is_uploaded=True,
        storage_metadata={"size": 128},
    )
    page = Page.objects.create(
        workspace=workspace,
        owned_by=create_user,
        access=Page.PUBLIC_ACCESS,
        name="Evidence page",
    )
    ProjectPage.objects.create(
        workspace=workspace,
        project=project,
        page=page,
    )
    return project, issue, attachment, page


@pytest.mark.contract
class TestIssueAttachmentPreview:
    @pytest.mark.django_db
    def test_admin_maps_and_reads_public_page_without_changing_original_asset(
        self, session_client, workspace, preview_context
    ):
        project, issue, attachment, page = preview_context
        original_asset = str(attachment.asset)
        url = _preview_url(workspace, project, issue, attachment)

        response = session_client.patch(
            url,
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)},
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {
            "preview_status": "ready",
            "preview_kind": "plane_page",
            "preview_page_id": str(page.id),
        }
        attachment.refresh_from_db()
        assert attachment.attributes == {
            "name": "evidence.pdf",
            "type": "application/pdf",
            "size": 128,
            "preview_kind": "plane_page",
            "preview_page_id": str(page.id),
        }
        assert str(attachment.asset) == original_asset

        readback = session_client.get(url)
        assert readback.status_code == status.HTTP_200_OK
        assert readback.json() == response.json()

        listing = session_client.get(_attachments_url(workspace, project, issue))
        assert listing.status_code == status.HTTP_200_OK
        listed_attachment = next(item for item in listing.json() if item["id"] == str(attachment.id))
        assert listed_attachment["attributes"]["preview_kind"] == "plane_page"
        assert listed_attachment["attributes"]["preview_page_id"] == str(page.id)

    @pytest.mark.django_db
    def test_clear_removes_only_preview_mapping_and_keeps_attachment(
        self, session_client, workspace, preview_context
    ):
        project, issue, attachment, page = preview_context
        attachment.attributes.update(
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)}
        )
        attachment.save(update_fields=["attributes", "updated_at"])
        url = _preview_url(workspace, project, issue, attachment)

        response = session_client.delete(url)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        attachment.refresh_from_db()
        assert attachment.attributes == {
            "name": "evidence.pdf",
            "type": "application/pdf",
            "size": 128,
        }
        assert FileAsset.objects.filter(id=attachment.id).exists()

    @pytest.mark.django_db
    def test_admin_cannot_map_private_page(
        self, session_client, workspace, preview_context
    ):
        project, issue, attachment, page = preview_context
        page.access = Page.PRIVATE_ACCESS
        page.save(update_fields=["access", "updated_at"])

        response = session_client.patch(
            _preview_url(workspace, project, issue, attachment),
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)},
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["code"] == "preview_target_invalid"
        attachment.refresh_from_db()
        assert "preview_page_id" not in attachment.attributes

    @pytest.mark.django_db
    def test_admin_cannot_map_page_from_another_project(
        self, session_client, workspace, create_user, preview_context
    ):
        project, issue, attachment, _ = preview_context
        other_project = Project.objects.create(
            name="Other project",
            identifier=f"OT{uuid4().hex[:6].upper()}",
            workspace=workspace,
        )
        other_page = Page.objects.create(
            workspace=workspace,
            owned_by=create_user,
            access=Page.PUBLIC_ACCESS,
            name="Other page",
        )
        ProjectPage.objects.create(
            workspace=workspace,
            project=other_project,
            page=other_page,
        )

        response = session_client.patch(
            _preview_url(workspace, project, issue, attachment),
            {"preview_kind": "plane_page", "preview_page_id": str(other_page.id)},
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["code"] == "preview_target_invalid"

    @pytest.mark.django_db
    def test_non_admin_cannot_create_or_clear_mapping(
        self, workspace, preview_context
    ):
        project, issue, attachment, page = preview_context
        member = User.objects.create(
            email=f"member-{uuid4().hex[:8]}@plane.so",
            username=f"member_{uuid4().hex[:8]}",
        )
        WorkspaceMember.objects.create(workspace=workspace, member=member, role=15)
        ProjectMember.objects.create(
            workspace=workspace,
            project=project,
            member=member,
            role=15,
        )
        client = APIClient()
        client.force_authenticate(user=member)
        url = _preview_url(workspace, project, issue, attachment)

        patch_response = client.patch(
            url,
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)},
            format="json",
        )
        delete_response = client.delete(url)

        assert patch_response.status_code == status.HTTP_403_FORBIDDEN
        assert delete_response.status_code == status.HTTP_403_FORBIDDEN
        attachment.refresh_from_db()
        assert "preview_page_id" not in attachment.attributes

    @pytest.mark.django_db
    def test_non_admin_cannot_bypass_preview_endpoint_through_generic_asset_patch(
        self, session_client, workspace, preview_context
    ):
        project, _, attachment, page = preview_context
        member = User.objects.create(
            email=f"member-{uuid4().hex[:8]}@plane.so",
            username=f"member_{uuid4().hex[:8]}",
        )
        WorkspaceMember.objects.create(workspace=workspace, member=member, role=15)
        ProjectMember.objects.create(
            workspace=workspace,
            project=project,
            member=member,
            role=15,
        )
        client = APIClient()
        client.force_authenticate(user=member)
        forged_attributes = dict(attachment.attributes)
        forged_attributes.update(
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)}
        )

        response = client.patch(
            _project_asset_url(workspace, project, attachment),
            {"attributes": forged_attributes},
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["code"] == "preview_mapping_requires_admin_endpoint"
        attachment.refresh_from_db()
        assert "preview_page_id" not in attachment.attributes

        admin_mapping = session_client.patch(
            _preview_url(workspace, project, attachment.issue, attachment),
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)},
            format="json",
        )
        assert admin_mapping.status_code == status.HTTP_200_OK

        generic_metadata_update = client.patch(
            _project_asset_url(workspace, project, attachment),
            {
                "attributes": {
                    "name": "renamed.pdf",
                    "type": "application/pdf",
                    "size": 128,
                }
            },
            format="json",
        )
        assert generic_metadata_update.status_code == status.HTTP_204_NO_CONTENT
        attachment.refresh_from_db()
        assert attachment.attributes["name"] == "renamed.pdf"
        assert attachment.attributes["preview_kind"] == "plane_page"
        assert attachment.attributes["preview_page_id"] == str(page.id)

    @pytest.mark.django_db
    def test_reader_gets_explicit_not_configured_and_invalid_statuses(
        self, session_client, workspace, preview_context
    ):
        project, issue, attachment, _ = preview_context
        url = _preview_url(workspace, project, issue, attachment)

        not_configured = session_client.get(url)
        assert not_configured.status_code == status.HTTP_404_NOT_FOUND
        assert not_configured.json()["preview_status"] == "not_configured"

        attachment.attributes.update(
            {"preview_kind": "external_url", "preview_page_id": "not-a-uuid"}
        )
        attachment.save(update_fields=["attributes", "updated_at"])
        invalid = session_client.get(url)
        assert invalid.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert invalid.json()["preview_status"] == "invalid"

        attachment.attributes = ["not", "an", "object"]
        attachment.save(update_fields=["attributes", "updated_at"])
        invalid_attributes = session_client.get(url)
        assert invalid_attributes.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert invalid_attributes.json()["code"] == "preview_mapping_invalid"

    @pytest.mark.django_db
    def test_reader_is_blocked_if_mapped_page_becomes_private_or_archived(
        self, session_client, workspace, preview_context
    ):
        project, issue, attachment, page = preview_context
        attachment.attributes.update(
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)}
        )
        attachment.save(update_fields=["attributes", "updated_at"])
        url = _preview_url(workspace, project, issue, attachment)

        page.access = Page.PRIVATE_ACCESS
        page.save(update_fields=["access", "updated_at"])
        forbidden = session_client.get(url)
        assert forbidden.status_code == status.HTTP_403_FORBIDDEN
        assert forbidden.json()["preview_status"] == "forbidden"

        page.access = Page.PUBLIC_ACCESS
        page.archived_at = timezone.localdate()
        page.save(update_fields=["access", "archived_at", "updated_at"])
        unavailable = session_client.get(url)
        assert unavailable.status_code == status.HTTP_410_GONE
        assert unavailable.json()["preview_status"] == "unavailable"

    @pytest.mark.django_db
    def test_known_asset_id_cannot_cross_issue_boundary(
        self, session_client, workspace, create_user, preview_context
    ):
        project, _, attachment, page = preview_context
        other_issue = Issue(name="Other issue", workspace=workspace, project=project)
        other_issue.save(created_by_id=create_user.id)
        attachment.attributes.update(
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)}
        )
        attachment.save(update_fields=["attributes", "updated_at"])

        response = session_client.get(
            _preview_url(workspace, project, other_issue, attachment)
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.django_db
    def test_unuploaded_asset_cannot_be_mapped_or_resolved(
        self, session_client, workspace, preview_context
    ):
        project, issue, attachment, page = preview_context
        attachment.is_uploaded = False
        attachment.save(update_fields=["is_uploaded", "updated_at"])
        url = _preview_url(workspace, project, issue, attachment)

        read_response = session_client.get(url)
        write_response = session_client.patch(
            url,
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)},
            format="json",
        )

        assert read_response.status_code == status.HTTP_404_NOT_FOUND
        assert write_response.status_code == status.HTTP_404_NOT_FOUND

        attachment.is_uploaded = True
        attachment.is_archived = True
        attachment.save(
            update_fields=["is_uploaded", "is_archived", "updated_at"]
        )
        archived_response = session_client.get(url)
        assert archived_response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.django_db
    def test_reader_is_blocked_if_page_or_project_link_is_soft_deleted(
        self, session_client, workspace, preview_context
    ):
        project, issue, attachment, page = preview_context
        attachment.attributes.update(
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)}
        )
        attachment.save(update_fields=["attributes", "updated_at"])
        url = _preview_url(workspace, project, issue, attachment)
        project_page = ProjectPage.objects.get(project=project, page=page)

        ProjectPage.all_objects.filter(id=project_page.id).update(
            deleted_at=timezone.now()
        )
        deleted_link = session_client.get(url)
        assert deleted_link.status_code == status.HTTP_410_GONE
        assert deleted_link.json()["preview_status"] == "unavailable"

        ProjectPage.all_objects.filter(id=project_page.id).update(deleted_at=None)
        Page.all_objects.filter(id=page.id).update(deleted_at=timezone.now())
        deleted_page = session_client.get(url)
        assert deleted_page.status_code == status.HTTP_410_GONE
        assert deleted_page.json()["preview_status"] == "unavailable"

    @pytest.mark.django_db
    def test_archived_or_soft_deleted_project_cannot_resolve_attachment(
        self, session_client, workspace, preview_context
    ):
        project, issue, attachment, page = preview_context
        attachment.attributes.update(
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)}
        )
        attachment.save(update_fields=["attributes", "updated_at"])
        url = _preview_url(workspace, project, issue, attachment)

        Project.all_objects.filter(id=project.id).update(archived_at=timezone.now())
        archived_project = session_client.get(url)
        assert archived_project.status_code == status.HTTP_404_NOT_FOUND

        Project.all_objects.filter(id=project.id).update(
            archived_at=None, deleted_at=timezone.now()
        )
        deleted_project = session_client.get(url)
        assert deleted_project.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.django_db
    def test_restricted_guest_cannot_resolve_foreign_issue_preview(
        self, workspace, preview_context
    ):
        project, issue, attachment, page = preview_context
        _, guest_client = _create_guest(workspace, project)
        attachment.attributes.update(
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)}
        )
        attachment.save(update_fields=["attributes", "updated_at"])

        response = guest_client.get(
            _preview_url(workspace, project, issue, attachment)
        )
        attachment_listing = guest_client.get(
            _attachments_url(workspace, project, issue)
        )
        download = guest_client.get(
            _attachment_download_url(workspace, project, issue, attachment)
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert attachment_listing.status_code == status.HTTP_403_FORBIDDEN
        assert download.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_restricted_guest_cannot_resolve_own_issue_preview_to_foreign_owned_page(
        self, monkeypatch, workspace, create_user, preview_context
    ):
        project, _, _, page = preview_context
        guest, guest_client = _create_guest(workspace, project)
        own_issue = Issue(
            name="Guest issue",
            workspace=workspace,
            project=project,
            created_by=guest,
        )
        own_issue.save(disable_auto_set_user=True)
        own_issue.refresh_from_db()
        assert own_issue.created_by_id == guest.id
        attachment = _create_uploaded_attachment(
            workspace, project, own_issue, create_user, name="guest.pdf"
        )
        attachment.attributes.update(
            {"preview_kind": "plane_page", "preview_page_id": str(page.id)}
        )
        attachment.save(update_fields=["attributes", "updated_at"])

        response = guest_client.get(
            _preview_url(workspace, project, own_issue, attachment)
        )
        attachment_listing = guest_client.get(
            _attachments_url(workspace, project, own_issue)
        )
        monkeypatch.setattr(
            "plane.app.views.issue.attachment.S3Storage.generate_presigned_url",
            lambda self, **kwargs: "https://storage.invalid/explicit-download",
        )
        download = guest_client.get(
            _attachment_download_url(
                workspace, project, own_issue, attachment
            )
        )
        page_response = guest_client.get(_page_url(workspace, project, page))

        assert page.owned_by_id != guest.id
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["code"] == "preview_target_forbidden"
        assert response.json()["preview_status"] == "forbidden"
        assert page_response.status_code == status.HTTP_403_FORBIDDEN
        assert attachment_listing.status_code == status.HTTP_200_OK
        assert str(attachment.id) in {
            item["id"] for item in attachment_listing.json()
        }
        assert download.status_code == status.HTTP_302_FOUND
        assert download["Location"] == "https://storage.invalid/explicit-download"

    @pytest.mark.django_db
    def test_archived_or_soft_deleted_issue_cannot_download_attachment(
        self, session_client, workspace, preview_context
    ):
        project, issue, attachment, _ = preview_context
        url = _attachment_download_url(workspace, project, issue, attachment)

        Issue.all_objects.filter(id=issue.id).update(
            archived_at=timezone.localdate()
        )
        archived_issue = session_client.get(url)
        assert archived_issue.status_code == status.HTTP_404_NOT_FOUND

        Issue.all_objects.filter(id=issue.id).update(
            archived_at=None, deleted_at=timezone.now()
        )
        deleted_issue = session_client.get(url)
        assert deleted_issue.status_code == status.HTTP_404_NOT_FOUND
