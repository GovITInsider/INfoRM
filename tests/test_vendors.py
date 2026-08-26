from inform.snmp.vendors import ENTERPRISE_VENDORS, vendor_from_sys_object_id


def test_day_one_map_strings():
    assert ENTERPRISE_VENDORS[9] == "Cisco"
    assert ENTERPRISE_VENDORS[25461] == "Palo Alto Networks"
    assert ENTERPRISE_VENDORS[2636] == "Juniper"
    assert ENTERPRISE_VENDORS[14823] == "Aruba (HPE)"
    assert ENTERPRISE_VENDORS[11] == "HP / HPE"
    assert ENTERPRISE_VENDORS[674] == "Dell"
    assert ENTERPRISE_VENDORS[12356] == "Fortinet"
    assert ENTERPRISE_VENDORS[318] == "APC"
    assert ENTERPRISE_VENDORS[3375] == "F5"
    assert ENTERPRISE_VENDORS[6876] == "VMware"
    assert ENTERPRISE_VENDORS[318] != "APC / Schneider"


def test_cisco_sysobjectid():
    assert vendor_from_sys_object_id("1.3.6.1.4.1.9.1.2694") == "Cisco"


def test_palo_alto_sysobjectid():
    assert vendor_from_sys_object_id("1.3.6.1.4.1.25461.2.3.29") == "Palo Alto Networks"


def test_apc_enterprise_318():
    assert vendor_from_sys_object_id("1.3.6.1.4.1.318.1.1.1") == "APC"


def test_leading_dot_oid():
    assert vendor_from_sys_object_id(".1.3.6.1.4.1.674.10892.5") == "Dell"


def test_unknown_enterprise():
    assert vendor_from_sys_object_id("1.3.6.1.4.1.8072.3.2.10") == "Unknown (8072)"


def test_empty_or_unparseable():
    assert vendor_from_sys_object_id(None) is None
    assert vendor_from_sys_object_id("") is None
    assert vendor_from_sys_object_id("   ") is None
    assert vendor_from_sys_object_id("not-an-oid") is None
    assert vendor_from_sys_object_id("1.3.6.1.2.1.1.1.0") is None
