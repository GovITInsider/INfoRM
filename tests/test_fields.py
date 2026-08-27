from inform.core.models import blank_to_none


def test_blank_to_none_empty_and_none_literal():
    assert blank_to_none(None) is None
    assert blank_to_none("") is None
    assert blank_to_none("   ") is None
    assert blank_to_none("None") is None
    assert blank_to_none("none") is None
    assert blank_to_none("NULL") is None


def test_blank_to_none_keeps_real_values():
    assert blank_to_none("YK-IOT-0031") == "YK-IOT-0031"
    assert blank_to_none("  rpi5  ") == "rpi5"
