import pytest
from types import SimpleNamespace


class _FakePub:
    def __init__(self, data):
        self._data = data

    def sec(self):
        return self._data


class _AddressFailureScript:
    def address(self, network=None):
        raise ValueError("no script address")


def _make_signer(PSBTSigner, bech32_hrp="tb"):
    signer = object.__new__(PSBTSigner)
    signer.wallet = SimpleNamespace(key=SimpleNamespace(network={"bech32": bech32_hrp}))
    signer.psbt = SimpleNamespace(
        inputs=[], outputs=[], sp_ecdh_shares={}, sp_dleq_proofs={}
    )
    return signer


def test_silent_payment_address_from_output_mainnet_prefix(m5stickv):
    from krux.psbt import PSBTSigner

    signer = _make_signer(PSBTSigner, bech32_hrp="bc")
    out = SimpleNamespace(
        sp_data=SimpleNamespace(
            scan_key=_FakePub(bytes.fromhex("02" + "11" * 32)),
            spend_key=_FakePub(bytes.fromhex("03" + "22" * 32)),
        )
    )

    addr = signer._silent_payment_address_from_output(out)
    assert addr.startswith("sp1")


def test_silent_payment_address_from_output_testnet_prefix(m5stickv):
    from krux.psbt import PSBTSigner

    signer = _make_signer(PSBTSigner, bech32_hrp="tb")
    out = SimpleNamespace(
        sp_data=SimpleNamespace(
            scan_key=_FakePub(bytes.fromhex("02" + "55" * 32)),
            spend_key=_FakePub(bytes.fromhex("03" + "66" * 32)),
        )
    )

    addr = signer._silent_payment_address_from_output(out)
    assert addr.startswith("tsp1")


def test_output_address_falls_back_to_silent_payment_address(m5stickv):
    from krux.psbt import PSBTSigner

    signer = _make_signer(PSBTSigner, bech32_hrp="tb")
    out = SimpleNamespace(
        sp_data=SimpleNamespace(
            scan_key=_FakePub(bytes.fromhex("02" + "33" * 32)),
            spend_key=_FakePub(bytes.fromhex("03" + "44" * 32)),
        )
    )
    signer.psbt = SimpleNamespace(
        tx=SimpleNamespace(
            vout=[SimpleNamespace(script_pubkey=_AddressFailureScript())]
        )
    )

    addr = signer._output_address(0, out)
    assert addr.startswith("tsp1")


def test_output_address_uses_script_pubkey_for_non_sp_output(m5stickv):
    """When sp_data is absent, _output_address must defer to script_pubkey.address()."""
    from krux.psbt import PSBTSigner

    class _NormalScript:
        def address(self, network=None):
            return "tb1qexampleaddress"

    signer = _make_signer(PSBTSigner, bech32_hrp="tb")
    out = SimpleNamespace()  # no sp_data attribute
    signer.psbt = SimpleNamespace(
        tx=SimpleNamespace(vout=[SimpleNamespace(script_pubkey=_NormalScript())])
    )

    assert signer._output_address(0, out) == "tb1qexampleaddress"


def test_validate_silent_payment_maps_validator_errors(m5stickv, monkeypatch):
    from krux.psbt import PSBTSigner
    from embit.bip375_validator import SPValidationError

    signer = _make_signer(PSBTSigner)
    signer.psbt = SimpleNamespace(
        sp_ecdh_shares={b"scan": b"share"},
        sp_dleq_proofs={},
        inputs=[],
        outputs=[],
    )

    class _BrokenValidator:
        def __init__(self, _psbt):
            pass

        def validate(self, skip_output_scripts=False):
            raise SPValidationError("bad fields")

    monkeypatch.setattr("embit.bip375_validator.BIP375Validator", _BrokenValidator)

    with pytest.raises(
        ValueError, match="Silent Payment validation failed: bad fields"
    ):
        signer._validate_silent_payment()


def test_validate_silent_payment_eligibility_rejects_multisig(m5stickv):
    """Multisig PSBT policies must be rejected when SP outputs are present."""
    from krux.psbt import PSBTSigner

    signer = _make_signer(PSBTSigner)
    signer.policy = {"type": "p2wsh", "m": 2, "n": 3}

    with pytest.raises(ValueError, match="multisig or miniscript"):
        signer._validate_silent_payment_eligibility()


def test_validate_silent_payment_eligibility_rejects_p2tr_input(m5stickv):
    """P2TR inputs are not BIP-375 eligible alongside SP outputs."""
    from krux.psbt import PSBTSigner

    signer = _make_signer(PSBTSigner)
    signer.policy = {"type": "p2tr"}

    with pytest.raises(ValueError, match="P2PKH, P2WPKH, or P2SH-P2WPKH"):
        signer._validate_silent_payment_eligibility()


def test_validate_silent_payment_eligibility_accepts_p2wpkh(m5stickv):
    """P2WPKH single-sig is the canonical SP-sender policy."""
    from krux.psbt import PSBTSigner

    signer = _make_signer(PSBTSigner)
    signer.policy = {"type": "p2wpkh"}

    # Should not raise
    signer._validate_silent_payment_eligibility()


def test_has_sp_outputs_detects_sp_data(m5stickv):
    from krux.psbt import PSBTSigner

    signer = _make_signer(PSBTSigner)
    signer.psbt = SimpleNamespace(
        outputs=[
            SimpleNamespace(sp_data=None),
            SimpleNamespace(sp_data=SimpleNamespace()),
        ]
    )

    assert signer.has_sp_outputs() is True


def test_has_sp_outputs_returns_false_when_attribute_missing(m5stickv):
    """Defensive: tolerate non-fork Embit OutputScope without sp_data attribute."""
    from krux.psbt import PSBTSigner

    signer = _make_signer(PSBTSigner)
    signer.psbt = SimpleNamespace(outputs=[SimpleNamespace(), SimpleNamespace()])

    assert signer.has_sp_outputs() is False
