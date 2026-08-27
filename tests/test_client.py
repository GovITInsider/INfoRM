from types import SimpleNamespace

from inform.snmp.client import (
    SnmpErrorKind,
    SnmpIdentity,
    _classify_error,
    apply_identity_to_device,
)


class _Err:
    def __init__(self, name: str, text: str):
        self.__class__ = type(name, (_Err,), {})
        self._text = text

    def __str__(self) -> str:
        return self._text


def test_classify_timeout():
    err = _Err("RequestTimedOut", "No SNMP response received before timeout")
    assert _classify_error(err, 0) is SnmpErrorKind.TIMEOUT


def test_classify_wrong_digest_is_auth():
    err = _Err("WrongDigest", "Wrong SNMP PDU digest")
    assert _classify_error(err, 0) is SnmpErrorKind.AUTH


def test_classify_missing_crypto_is_not_timeout():
    err = _Err("EncryptionError", "Ciphering services not available")
    assert _classify_error(err, 0) is SnmpErrorKind.OTHER


def test_classify_unsupported_priv_is_not_timeout():
    err = _Err("UnsupportedPrivProtocol", "Privacy protocol not supported")
    assert _classify_error(err, 0) is SnmpErrorKind.OTHER


def _device(**kwargs):
    defaults = dict(
        name="custom",
        location="old-loc",
        vendor=None,
        model=None,
        sys_object_id=None,
        credential_profile_id=1,
        comment="keep-me",
        building="HQ",
        asset_tag="TAG-1",
        monitored=True,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _identity():
    return SnmpIdentity(
        sys_name="rpi5",
        sys_location="MDF",
        sys_object_id="1.3.6.1.4.1.8072.3.2.10",
        vendor="Unknown (8072)",
        model=None,
        profile_id=9,
    )


def test_apply_identity_overwrites_location_vendor_model_not_name():
    device = _device()
    apply_identity_to_device(device, _identity())
    assert device.location == "MDF"
    assert device.vendor == "Unknown (8072)"
    assert device.model is None
    assert device.sys_object_id == "1.3.6.1.4.1.8072.3.2.10"
    assert device.credential_profile_id == 9
    assert device.name == "custom"
    assert device.comment == "keep-me"
    assert device.building == "HQ"
    assert device.asset_tag == "TAG-1"
    assert device.monitored is True


def test_apply_identity_update_name_overwrites():
    device = _device(name="custom")
    apply_identity_to_device(device, _identity(), update_name=True)
    assert device.name == "rpi5"


def test_apply_identity_fills_blank_name_only():
    device = _device(name="  ")
    apply_identity_to_device(device, _identity(), fill_name_if_empty=True)
    assert device.name == "rpi5"
    device = _device(name="keep")
    apply_identity_to_device(device, _identity(), fill_name_if_empty=True)
    assert device.name == "keep"
