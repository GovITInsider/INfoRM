from inform.snmp.identity import EntityRow, model_from_sysdescr, pick_chassis_model


def test_fast_path_index_1_chassis():
    rows = [
        EntityRow(index=1, physical_class=3, model_name="C9300-48P", contained_in=0),
        EntityRow(index=2, physical_class=10, model_name="C9300-48P", contained_in=1),
    ]
    assert pick_chassis_model(rows) == "C9300-48P"


def test_prefer_rooted_chassis_lowest_index():
    rows = [
        EntityRow(index=1000, physical_class=3, model_name="C9200-24P", contained_in=0),
        EntityRow(index=2, physical_class=3, model_name="C9300-48P", contained_in=0),
        EntityRow(index=3, physical_class=10, model_name="PORT-1", contained_in=2),
    ]
    assert pick_chassis_model(rows) == "C9300-48P"


def test_nested_chassis_falls_back_to_lowest_index():
    rows = [
        EntityRow(index=5, physical_class=3, model_name="MEMBER-2", contained_in=1),
        EntityRow(index=2, physical_class=3, model_name="MEMBER-1", contained_in=1),
    ]
    assert pick_chassis_model(rows) == "MEMBER-1"


def test_stack_fallback_when_no_chassis():
    rows = [
        EntityRow(index=1, physical_class=11, model_name="Stack1", contained_in=0),
        EntityRow(index=10, physical_class=10, model_name="Gi1/0/1", contained_in=1),
    ]
    assert pick_chassis_model(rows) == "Stack1"


def test_ignore_ports_even_with_model_string():
    rows = [
        EntityRow(index=1, physical_class=10, model_name="WS-C3750", contained_in=0),
        EntityRow(index=2, physical_class=6, model_name="FAN-TRAY", contained_in=0),
    ]
    assert pick_chassis_model(rows) is None


def test_empty_model_names_yield_none():
    rows = [
        EntityRow(index=1, physical_class=3, model_name="  ", contained_in=0),
        EntityRow(index=2, physical_class=3, model_name=None, contained_in=0),
    ]
    assert pick_chassis_model(rows) is None


def test_strips_quotes_and_truncates():
    rows = [
        EntityRow(index=1, physical_class=3, model_name='"C9300-48P"', contained_in=0),
    ]
    assert pick_chassis_model(rows) == "C9300-48P"


def test_sysdescr_cisco():
    assert model_from_sysdescr("Cisco", "Cisco IOS Software, C9300-48P Software") == "C9300-48P"
    assert model_from_sysdescr("Cisco", "Cisco IOS Software, WS-C2960X-48FPD-L") == "WS-C2960X-48FPD-L"
    assert model_from_sysdescr("Cisco", "Cisco IOS Software, ISR4331/K9") == "ISR4331"


def test_sysdescr_cisco_iosxe_without_sku():
    descr = (
        "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software "
        "(CAT9K_IOSXE), Version 17.9.4a"
    )
    assert model_from_sysdescr("Cisco", descr) is None


def test_sysdescr_other_vendors():
    assert model_from_sysdescr("Palo Alto Networks", "Palo Alto Networks PA-3220") == "PA-3220"
    assert model_from_sysdescr("Fortinet", "FortiGate-100F") == "FortiGate-100F"
    assert model_from_sysdescr("Aruba (HPE)", "Aruba JL357A Switch") == "JL357A"
    assert model_from_sysdescr("Juniper", "Juniper Networks, Inc. EX4300-48P") == "EX4300-48P"
    assert model_from_sysdescr("F5", "Linux BIG-IP") == "BIG-IP"


def test_sysdescr_no_pattern_for_apc_or_unknown():
    assert model_from_sysdescr("APC", "APC Web/SNMP Management Card") is None
    assert model_from_sysdescr("Unknown (8072)", "Linux net-snmp") is None
    assert model_from_sysdescr(None, "C9300-48P") is None
