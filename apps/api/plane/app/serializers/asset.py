# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from rest_framework import serializers

from .base import BaseSerializer
from plane.db.models import FileAsset


ISSUE_ATTACHMENT_PREVIEW_ATTRIBUTE_KEYS = frozenset(
    {"preview_kind", "preview_page_id"}
)


def has_controlled_preview_attributes(attributes):
    return isinstance(attributes, dict) and bool(
        ISSUE_ATTACHMENT_PREVIEW_ATTRIBUTE_KEYS.intersection(attributes)
    )


def merge_attributes_preserving_controlled_preview(current_attributes, requested_attributes):
    """Merge generic metadata without allowing preview mapping mutations.

    Returns ``(merged_attributes, attempted_mutation)``. Existing preview
    fields survive a generic metadata update even if the caller omits them.
    """

    current = current_attributes if isinstance(current_attributes, dict) else {}
    current_preview = {
        key: current[key]
        for key in ISSUE_ATTACHMENT_PREVIEW_ATTRIBUTE_KEYS
        if key in current
    }
    if not isinstance(requested_attributes, dict):
        return requested_attributes, bool(current_preview)

    requested_preview = {
        key: requested_attributes[key]
        for key in ISSUE_ATTACHMENT_PREVIEW_ATTRIBUTE_KEYS
        if key in requested_attributes
    }
    if requested_preview and requested_preview != current_preview:
        return requested_attributes, True

    merged = dict(requested_attributes)
    merged.update(current_preview)
    return merged, False


class FileAssetSerializer(BaseSerializer):
    def validate_attributes(self, attributes):
        entity_type = (
            self.instance.entity_type
            if self.instance is not None
            else self.initial_data.get("entity_type")
        )
        if entity_type != FileAsset.EntityTypeContext.ISSUE_ATTACHMENT:
            return attributes

        if self.instance is not None:
            attributes, attempted_mutation = merge_attributes_preserving_controlled_preview(
                self.instance.attributes,
                attributes,
            )
        else:
            attempted_mutation = has_controlled_preview_attributes(attributes)
        if attempted_mutation:
            raise serializers.ValidationError(
                "Attachment preview mappings must use the controlled preview endpoint."
            )
        return attributes

    class Meta:
        model = FileAsset
        fields = "__all__"
        read_only_fields = ["created_by", "updated_by", "created_at", "updated_at"]
