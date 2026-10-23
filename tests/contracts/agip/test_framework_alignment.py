from agip_core.domain.framework_alignment import FrameworkAlignment
from agip_core.core.governance.framework_validator import FrameworkValidator, FrameworkAlignmentError


def test_alignment_requires_existing_controls():
    alignment = FrameworkAlignment(
        alignment_id="fa_001",
        framework="nist_ai_rmf",
        version="1.0",
        enabled=True,
        control_mappings=["missing_map"],
    )
    try:
        FrameworkValidator().validate(alignment, {})
        assert False
    except FrameworkAlignmentError:
        assert True