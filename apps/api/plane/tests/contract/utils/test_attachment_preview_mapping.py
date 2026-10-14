# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Shared contracts for attachment preview mapping state and metadata."""

from uuid import UUID, uuid4

import pytest

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
from plane.utils.attachment_preview import (
    PREVIEW_KIND,
    PREVIEW_KIND_KEY,
    PREVIEW_PAGE_EXTERNAL_SOURCE,
    PREVIEW_PAGE_ID,
    PreviewAttributesInvalid,
    clear_preview_mapping,
    resolve_preview_mapping,
    set_preview_mapping,
    with_preview_mapping,
    without_preview_mapping,
)


@pytest.fixture
def preview_mapping_context(db, workspace, create_user):
    project = Project.objects.create(
        name="Shared preview state",
        identifier=f"SM{uuid4().hex[:6].upper()}",
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
        name="Shared preview source",
        sequence_id=1,
        workspace=workspace,
        project=project,
        created_by=create_user,
    )
    attachment = FileAsset.objects.create(
        attributes={"name": "evidence.txt", "type": "text/plain", "size": 12},
        asset=f"{workspace.id}/shared-preview.txt",
        size=12,
        workspace=workspace,
        project=project,
        issue=issue,
        created_by=create_user,
        entity_type=FileAsset.EntityTypeContext.ISSUE_ATTACHMENT,
        is_uploaded=True,
        storage_metadata={"size": 12},
    )
    page = Page.objects.create(
        workspace=workspace,
        owned_by=create_user,
        access=Page.PUBLIC_ACCESS,
        name="Shared preview page",
    )
    ProjectPage.objects.create(
        workspace=workspace,
        project=project,
        page=page,
    )
    return project, issue, attachment, page


@pytest.mark.contract
class TestAttachmentPreviewMappingState:
    @pytest.mark.django_db
    @pytest.mark.parametrize(
        ("attributes", "expected_state", "expected_code"),
        [
            (None, "not_configured", "preview_not_configured"),
            ({}, "not_configured", "preview_not_configured"),
            ([], "invalid", "preview_mapping_invalid"),
            ({PREVIEW_KIND_KEY: PREVIEW_KIND}, "invalid", "preview_mapping_invalid"),
            ({PREVIEW_PAGE_ID: "00000000-0000-0000-0000-000000000001"}, "invalid", "preview_mapping_invalid"),
            (
                {
                    PREVIEW_KIND_KEY: "external_url",
                    PREVIEW_PAGE_ID: "00000000-0000-0000-0000-000000000001",
                },
                "invalid",
                "preview_mapping_invalid",
            ),
            (
                {PREVIEW_KIND_KEY: PREVIEW_KIND, PREVIEW_PAGE_ID: "not-a-uuid"},
                "invalid",
                "preview_mapping_invalid",
            ),
        ],
    )
    def test_mapping_syntax_states(
        self,
        workspace,
        create_user,
        preview_mapping_context,
        attributes,
        expected_state,
        expected_code,
    ):
        project, _, attachment, _ = preview_mapping_context
        attachment.attributes = attributes

        decision = resolve_preview_mapping(
            user=create_user,
            attachment=attachment,
            slug=workspace.slug,
            project_id=project.id,
        )

        assert decision.state == expected_state
        assert decision.code == expected_code
        assert decision.page_id is None

    @pytest.mark.django_db
    def test_ready_private_and_unavailable_target_states(
        self, workspace, create_user, preview_mapping_context
    ):
        project, _, attachment, page = preview_mapping_context
        attachment.attributes = with_preview_mapping(attachment.attributes, page.id)

        ready = resolve_preview_mapping(
            user=create_user,
            attachment=attachment,
            slug=workspace.slug,
            project_id=project.id,
        )
        assert ready.state == "ready"
        assert ready.page_id == page.id

        page.access = Page.PRIVATE_ACCESS
        page.save(update_fields=["access", "updated_at"])
        private = resolve_preview_mapping(
            user=create_user,
            attachment=attachment,
            slug=workspace.slug,
            project_id=project.id,
        )
        assert private.state == "forbidden"
        assert private.code == "preview_target_forbidden"
        assert private.reason == "target_not_public"

        attachment.attributes = with_preview_mapping(
            attachment.attributes,
            UUID("00000000-0000-0000-0000-000000000001"),
        )
        unavailable = resolve_preview_mapping(
            user=create_user,
            attachment=attachment,
            slug=workspace.slug,
            project_id=project.id,
        )
        assert unavailable.state == "unavailable"
        assert unavailable.code == "preview_target_unavailable"

    @pytest.mark.django_db
    def test_restricted_guest_page_acl_and_derived_page_positive_control(
        self, workspace, create_user, preview_mapping_context
    ):
        project, issue, attachment, ordinary_page = preview_mapping_context
        guest = User.objects.create(
            email=f"shared-preview-{uuid4().hex[:8]}@plane.so",
            username=f"shared_preview_{uuid4().hex[:8]}",
        )
        WorkspaceMember.objects.create(workspace=workspace, member=guest, role=5)
        ProjectMember.objects.create(
            workspace=workspace,
            project=project,
            member=guest,
            role=5,
        )
        Issue.objects.filter(id=issue.id).update(created_by=guest)
        issue.refresh_from_db()
        attachment.issue = issue
        attachment.attributes = with_preview_mapping(
            attachment.attributes,
            ordinary_page.id,
        )

        forbidden = resolve_preview_mapping(
            user=guest,
            attachment=attachment,
            slug=workspace.slug,
            project_id=project.id,
        )
        assert ordinary_page.owned_by_id != guest.id
        assert forbidden.state == "forbidden"
        assert forbidden.reason == "page_acl"

        derived_page = Page.objects.create(
            workspace=workspace,
            owned_by=create_user,
            access=Page.PUBLIC_ACCESS,
            name="Derived source projection",
            external_source=PREVIEW_PAGE_EXTERNAL_SOURCE,
            external_id=str(attachment.id),
        )
        ProjectPage.objects.create(
            workspace=workspace,
            project=project,
            page=derived_page,
        )
        attachment.attributes = with_preview_mapping(
            attachment.attributes,
            derived_page.id,
        )
        ready = resolve_preview_mapping(
            user=guest,
            attachment=attachment,
            slug=workspace.slug,
            project_id=project.id,
        )
        assert ready.state == "ready"
        assert ready.page_id == derived_page.id


@pytest.mark.contract
class TestAttachmentPreviewAttributes:
    def test_set_and_clear_are_pure_and_preserve_unrelated_metadata(self):
        old_page_id = uuid4()
        new_page_id = uuid4()
        original = {
            "name": "evidence.txt",
            "type": "text/plain",
            "size": 12,
            PREVIEW_KIND_KEY: PREVIEW_KIND,
            PREVIEW_PAGE_ID: str(old_page_id),
        }

        mapped = with_preview_mapping(original, new_page_id)
        cleared = without_preview_mapping(mapped)

        assert mapped is not original
        assert original[PREVIEW_PAGE_ID] == str(old_page_id)
        assert mapped[PREVIEW_PAGE_ID] == str(new_page_id)
        assert cleared == {
            "name": "evidence.txt",
            "type": "text/plain",
            "size": 12,
        }
        assert mapped[PREVIEW_PAGE_ID] == str(new_page_id)

    @pytest.mark.parametrize("attributes", [[], "invalid", 1])
    def test_non_mapping_attributes_fail_closed_without_mutation(self, attributes):
        with pytest.raises(PreviewAttributesInvalid):
            with_preview_mapping(attributes, uuid4())
        with pytest.raises(PreviewAttributesInvalid):
            without_preview_mapping(attributes)


@pytest.mark.contract
@pytest.mark.django_db
class TestAttachmentPreviewMappingMutation:
    def test_set_and_clear_preserve_unrelated_metadata(
        self, workspace, create_user, preview_mapping_context
    ):
        project, issue, attachment, page = preview_mapping_context

        mapped = set_preview_mapping(
            user=create_user,
            slug=workspace.slug,
            project_id=project.id,
            issue_id=issue.id,
            asset_id=attachment.id,
            page_id=page.id,
        )
        attachment.refresh_from_db()

        assert mapped.state == "ready"
        assert mapped.page_id == page.id
        assert attachment.attributes == {
            "name": "evidence.txt",
            "type": "text/plain",
            "size": 12,
            PREVIEW_KIND_KEY: PREVIEW_KIND,
            PREVIEW_PAGE_ID: str(page.id),
        }

        cleared = clear_preview_mapping(
            slug=workspace.slug,
            project_id=project.id,
            issue_id=issue.id,
            asset_id=attachment.id,
        )
        attachment.refresh_from_db()

        assert cleared.state == "ready"
        assert attachment.attributes == {
            "name": "evidence.txt",
            "type": "text/plain",
            "size": 12,
        }

    def test_set_rejects_missing_or_inaccessible_target(
        self, workspace, create_user, preview_mapping_context
    ):
        project, issue, attachment, page = preview_mapping_context
        missing = set_preview_mapping(
            user=create_user,
            slug=workspace.slug,
            project_id=project.id,
            issue_id=issue.id,
            asset_id=attachment.id,
            page_id=uuid4(),
        )
        assert missing.state == "target_invalid"
        assert missing.code == "preview_target_invalid"

        page.access = Page.PRIVATE_ACCESS
        page.save(update_fields=["access", "updated_at"])
        inaccessible = set_preview_mapping(
            user=create_user,
            slug=workspace.slug,
            project_id=project.id,
            issue_id=issue.id,
            asset_id=attachment.id,
            page_id=page.id,
        )
        assert inaccessible.state == "target_invalid"
        assert inaccessible.code == "preview_target_invalid"

        attachment.refresh_from_db()
        assert PREVIEW_KIND_KEY not in attachment.attributes
        assert PREVIEW_PAGE_ID not in attachment.attributes

    def test_set_enforces_current_users_page_acl(
        self, workspace, create_user, preview_mapping_context
    ):
        project, issue, attachment, page = preview_mapping_context
        guest = User.objects.create(
            email=f"mutation-guest-{uuid4().hex[:8]}@plane.so",
            username=f"mutation_guest_{uuid4().hex[:8]}",
        )
        WorkspaceMember.objects.create(workspace=workspace, member=guest, role=5)
        ProjectMember.objects.create(
            workspace=workspace,
            project=project,
            member=guest,
            role=5,
        )

        decision = set_preview_mapping(
            user=guest,
            slug=workspace.slug,
            project_id=project.id,
            issue_id=issue.id,
            asset_id=attachment.id,
            page_id=page.id,
        )

        assert page.access == Page.PUBLIC_ACCESS
        assert page.owned_by_id != guest.id
        assert decision.state == "target_invalid"
        assert decision.code == "preview_target_invalid"
        attachment.refresh_from_db()
        assert PREVIEW_KIND_KEY not in attachment.attributes
        assert PREVIEW_PAGE_ID not in attachment.attributes

        WorkspaceMember.objects.filter(workspace=workspace, member=guest).update(
            role=20
        )
        workspace_admin = set_preview_mapping(
            user=guest,
            slug=workspace.slug,
            project_id=project.id,
            issue_id=issue.id,
            asset_id=attachment.id,
            page_id=page.id,
        )
        attachment.refresh_from_db()
        resolved = resolve_preview_mapping(
            user=guest,
            attachment=attachment,
            slug=workspace.slug,
            project_id=project.id,
        )

        assert workspace_admin.state == "ready"
        assert workspace_admin.page_id == page.id
        assert resolved.state == "ready"
        assert resolved.page_id == page.id

    def test_set_and_clear_return_not_found_for_exact_attachment_boundary(
        self, workspace, create_user, preview_mapping_context
    ):
        project, issue, _, page = preview_mapping_context
        missing_id = uuid4()

        mapped = set_preview_mapping(
            user=create_user,
            slug=workspace.slug,
            project_id=project.id,
            issue_id=issue.id,
            asset_id=missing_id,
            page_id=page.id,
        )
        cleared = clear_preview_mapping(
            slug=workspace.slug,
            project_id=project.id,
            issue_id=issue.id,
            asset_id=missing_id,
        )

        assert mapped.state == "not_found"
        assert mapped.code == "attachment_not_found"
        assert cleared.state == "not_found"
        assert cleared.code == "attachment_not_found"

    @pytest.mark.parametrize("operation", ["set", "clear"])
    def test_mutation_rejects_invalid_attributes(
        self, workspace, create_user, preview_mapping_context, operation
    ):
        project, issue, attachment, page = preview_mapping_context
        FileAsset.objects.filter(id=attachment.id).update(attributes=[])

        if operation == "set":
            decision = set_preview_mapping(
                user=create_user,
                slug=workspace.slug,
                project_id=project.id,
                issue_id=issue.id,
                asset_id=attachment.id,
                page_id=page.id,
            )
        else:
            decision = clear_preview_mapping(
                slug=workspace.slug,
                project_id=project.id,
                issue_id=issue.id,
                asset_id=attachment.id,
            )

        assert decision.state == "attributes_invalid"
        assert decision.code == "attachment_attributes_invalid"
