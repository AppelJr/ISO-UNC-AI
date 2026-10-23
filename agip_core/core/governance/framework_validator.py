from agip_core.domain.framework_alignment import FrameworkAlignment


class FrameworkAlignmentError(Exception):
    pass


class FrameworkValidator:
    def validate(self, alignment: FrameworkAlignment, mappings: dict):
        if not alignment.enabled:
            raise FrameworkAlignmentError("Framework disabled")
        for mapping_id in alignment.control_mappings:
            if mapping_id not in mappings:
                raise FrameworkAlignmentError(f"Missing control mapping: {mapping_id}")
        return alignment