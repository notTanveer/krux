import base64
import pytest
from types import SimpleNamespace

# abandon × 11 + "about"; testnet singlesig, fingerprint 73c5da0a
TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about"
)

# Scan/spend keys for a fake SP recipient (deterministic: priv = 0x01…01 / 0x02…02)
_SCAN_PUB_HEX = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
_SPEND_PUB_HEX = "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"


def _build_sp_psbt_bytes():
    """Return raw bytes for a PSBTv2 with one P2WPKH input + one SP output.

    Input key: m/84h/1h/0h/0/0 under the abandon×11+about mnemonic (testnet).
    SP output: 99 000 sat, placeholder P2TR script, scan=0x01…, spend=0x02….
    tx_modifiable_flags=0 marks it as final (required by BIP-375 Stage 3).
    """
    import sys

    sys.path.insert(0, "vendor/embit/src")
    from embit.bip32 import HDKey, parse_path
    from embit.bip39 import mnemonic_to_seed
    from embit.psbt import DerivationPath
    from embit.silent_payments import (
        SilentPaymentData,
        SilentPaymentsPSBT as PSBT,
        SPInputScope as InputScope,
        SPOutputScope as OutputScope,
    )
    from embit import ec
    from embit.script import p2wpkh, Script
    from embit.transaction import TransactionOutput

    seed = mnemonic_to_seed(TEST_MNEMONIC)
    root = HDKey.from_seed(seed)
    fingerprint = root.child(0).fingerprint
    child = root.derive("m/84h/1h/0h/0/0")
    pub = child.get_public_key()

    scan_pub = ec.PublicKey.parse(bytes.fromhex(_SCAN_PUB_HEX))
    spend_pub = ec.PublicKey.parse(bytes.fromhex(_SPEND_PUB_HEX))

    psbt = PSBT.create_v2()

    inp = InputScope()
    inp.txid = bytes(32)
    inp.vout = 0
    inp.sequence = 0xFFFFFFFE
    inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2wpkh(pub))
    inp.bip32_derivations[pub] = DerivationPath(
        fingerprint, parse_path("m/84h/1h/0h/0/0")
    )
    psbt.add_input(inp)

    out = OutputScope()
    out.value = 99_000
    out.script_pubkey = Script(b"\x51\x20" + bytes(32))  # placeholder P2TR
    out.sp_data = SilentPaymentData(scan_pub, spend_pub)
    psbt.add_output(out)
    psbt.tx_modifiable_flags = 0

    return psbt.serialize()


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
    from embit.silent_payments import SPValidationError

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

    monkeypatch.setattr("embit.silent_payments.BIP375Validator", _BrokenValidator)

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


# ---------------------------------------------------------------------------
# End-to-end SP signing tests using the real PSBTSigner + Krux wallet
# ---------------------------------------------------------------------------


def _make_sp_wallet():
    """Return a Krux Wallet loaded with the abandon×11+about mnemonic (testnet)."""
    from embit.networks import NETWORKS
    from krux.key import Key, TYPE_SINGLESIG
    from krux.wallet import Wallet

    return Wallet(Key(TEST_MNEMONIC, TYPE_SINGLESIG, NETWORKS["test"]))


def test_sp_signing_detects_sp_outputs(m5stickv):
    """PSBTSigner must recognise the SP output at load time."""
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE

    wallet = _make_sp_wallet()
    raw = _build_sp_psbt_bytes()
    signer = PSBTSigner(wallet, raw, FORMAT_NONE)
    assert signer.has_sp_outputs()


def test_sp_signing_p2wpkh_adds_ecdh_shares(m5stickv):
    """After sign(), every input must carry an ECDH share for the SP scan key."""
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE

    wallet = _make_sp_wallet()
    raw = _build_sp_psbt_bytes()
    signer = PSBTSigner(wallet, raw, FORMAT_NONE)
    signer.sign()

    scan_key_bytes = bytes.fromhex(_SCAN_PUB_HEX)
    inp = signer.psbt.inputs[0]

    assert scan_key_bytes in inp.sp_ecdh_shares
    share = inp.sp_ecdh_shares[scan_key_bytes]
    assert len(share) == 33, "ECDH share must be a compressed EC point (33 bytes)"


def test_sp_signing_adds_dleq_proofs(m5stickv):
    """After sign(), every input must carry a DLEQ proof for the SP scan key."""
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE

    wallet = _make_sp_wallet()
    raw = _build_sp_psbt_bytes()
    signer = PSBTSigner(wallet, raw, FORMAT_NONE)
    signer.sign()

    scan_key_bytes = bytes.fromhex(_SCAN_PUB_HEX)
    inp = signer.psbt.inputs[0]

    assert scan_key_bytes in inp.sp_dleq_proofs
    proof = inp.sp_dleq_proofs[scan_key_bytes]
    assert len(proof) == 64, "DLEQ proof must be 64 bytes (two 32-byte scalars)"


def test_sp_signing_discards_incoming_fields(m5stickv):
    """Coordinator-supplied SP fields must be discarded and replaced by Krux-derived ones."""
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE

    wallet = _make_sp_wallet()
    raw = _build_sp_psbt_bytes()
    signer = PSBTSigner(wallet, raw, FORMAT_NONE)

    # Pre-populate the parsed PSBT with fake coordinator-supplied SP fields.
    dummy_scan = b"\x02" + b"\xff" * 32  # recognisably wrong key
    signer.psbt.inputs[0].sp_ecdh_shares[dummy_scan] = b"\x03" + b"\xaa" * 32
    signer.psbt.inputs[0].sp_dleq_proofs[dummy_scan] = b"\xbb" * 64

    signer.sign()

    scan_key_bytes = bytes.fromhex(_SCAN_PUB_HEX)
    inp = signer.psbt.inputs[0]

    # Dummy key must be gone; real scan key must be present.
    assert dummy_scan not in inp.sp_ecdh_shares
    assert scan_key_bytes in inp.sp_ecdh_shares


def test_sp_signing_preserves_psbt_version_2(m5stickv):
    """Trimmed PSBT after sign() must remain PSBTv2 (version field == 2)."""
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE

    wallet = _make_sp_wallet()
    raw = _build_sp_psbt_bytes()
    signer = PSBTSigner(wallet, raw, FORMAT_NONE)
    signer.sign()

    assert signer.psbt.version == 2


def test_sp_fields_survive_serialization(m5stickv):
    """SP ECDH shares and DLEQ proofs must survive a serialize → parse round-trip."""
    from embit.silent_payments import SilentPaymentsPSBT as PSBT
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE

    wallet = _make_sp_wallet()
    raw = _build_sp_psbt_bytes()
    signer = PSBTSigner(wallet, raw, FORMAT_NONE)
    signer.sign()

    scan_key_bytes = bytes.fromhex(_SCAN_PUB_HEX)
    original_share = signer.psbt.inputs[0].sp_ecdh_shares[scan_key_bytes]

    # Round-trip through serialization.
    reparsed = PSBT.parse(signer.psbt.serialize())
    assert reparsed.version == 2
    assert scan_key_bytes in reparsed.inputs[0].sp_ecdh_shares
    assert reparsed.inputs[0].sp_ecdh_shares[scan_key_bytes] == original_share


def test_sp_signing_also_signs_input(m5stickv):
    """After sign(), the P2WPKH input must carry a partial signature (witness sig)."""
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE

    wallet = _make_sp_wallet()
    raw = _build_sp_psbt_bytes()
    signer = PSBTSigner(wallet, raw, FORMAT_NONE)
    signer.sign()

    inp = signer.psbt.inputs[0]
    has_partial = bool(inp.partial_sigs)
    has_witness = bool(inp.final_scriptwitness)
    assert has_partial or has_witness, "Input must be signed after sign()"


def _build_sparrow_style_sp_psbt():
    """Build PSBTv2 bytes mimicking Sparrow: SP output OMITS PSBT_OUT_SCRIPT.

    BIP-375 says the signer derives the P2TR output script after ECDH.
    Sparrow as the coordinator omits PSBT_OUT_SCRIPT for the SP output,
    leaving it for the signing device to fill.
    """
    import sys
    from io import BytesIO

    sys.path.insert(0, "vendor/embit/src")
    from embit.bip32 import HDKey, parse_path
    from embit.bip39 import mnemonic_to_seed
    from embit.psbt import DerivationPath, ser_string
    from embit.silent_payments import (
        SilentPaymentData,
        SilentPaymentsPSBT as PSBT,
        SPInputScope as InputScope,
        SPOutputScope as OutputScope,
    )
    from embit import ec
    from embit.script import p2wpkh, Script
    from embit.transaction import TransactionOutput

    seed = mnemonic_to_seed(TEST_MNEMONIC)
    root = HDKey.from_seed(seed)
    fingerprint = root.child(0).fingerprint
    child = root.derive("m/84h/1h/0h/0/0")
    pub = child.get_public_key()

    scan_pub = ec.PublicKey.parse(bytes.fromhex(_SCAN_PUB_HEX))
    spend_pub = ec.PublicKey.parse(bytes.fromhex(_SPEND_PUB_HEX))

    psbt = PSBT.create_v2()

    inp = InputScope()
    inp.txid = bytes(32)
    inp.vout = 0
    inp.sequence = 0xFFFFFFFE
    inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2wpkh(pub))
    inp.bip32_derivations[pub] = DerivationPath(
        fingerprint, parse_path("m/84h/1h/0h/0/0")
    )
    psbt.add_input(inp)

    # SP output: has sp_data but NO script_pubkey (Sparrow omits PSBT_OUT_SCRIPT)
    out = OutputScope()
    out.value = 99_000
    out.script_pubkey = None  # deliberately absent
    out.sp_data = SilentPaymentData(scan_pub, spend_pub)
    psbt.add_output(out)
    psbt.tx_modifiable_flags = 0

    return psbt.serialize()


def test_sp_psbt_v2_absent_script_parseable(m5stickv):
    """PSBTv2 with SP output that omits PSBT_OUT_SCRIPT must parse successfully.

    This tests interoperability with coordinators (like Sparrow) that omit
    PSBT_OUT_SCRIPT for SP outputs, expecting the signer to derive it.
    """
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE

    wallet = _make_sp_wallet()
    raw = _build_sparrow_style_sp_psbt()
    signer = PSBTSigner(wallet, raw, FORMAT_NONE)

    assert signer.psbt.version == 2
    assert signer.psbt.outputs[0].sp_data is not None
    assert signer.psbt.outputs[0].script_pubkey is None


def test_sp_signing_absent_script_full_flow(m5stickv):
    """Sparrow-style SP PSBT (absent script_pubkey) must sign end-to-end."""
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE

    wallet = _make_sp_wallet()
    raw = _build_sparrow_style_sp_psbt()
    signer = PSBTSigner(wallet, raw, FORMAT_NONE)
    signer.sign()

    scan_key_bytes = bytes.fromhex(_SCAN_PUB_HEX)
    inp = signer.psbt.inputs[0]
    assert scan_key_bytes in inp.sp_ecdh_shares
    has_partial = bool(inp.partial_sigs)
    has_witness = bool(inp.final_scriptwitness)
    assert has_partial or has_witness


def _build_sp_psbt_with_p2tr_input():
    """Build PSBTv2 with a P2TR input + SP output (BIP-375 invalid)."""
    import sys

    sys.path.insert(0, "vendor/embit/src")
    from embit.bip32 import HDKey, parse_path
    from embit.bip39 import mnemonic_to_seed
    from embit.psbt import DerivationPath
    from embit.silent_payments import (
        SilentPaymentData,
        SilentPaymentsPSBT as PSBT,
        SPInputScope as InputScope,
        SPOutputScope as OutputScope,
    )
    from embit import ec
    from embit.script import Script
    from embit.transaction import TransactionOutput

    seed = mnemonic_to_seed(TEST_MNEMONIC)
    root = HDKey.from_seed(seed)
    fingerprint = root.child(0).fingerprint
    child = root.derive("m/86h/1h/0h/0/0")
    pub = child.get_public_key()

    scan_pub = ec.PublicKey.parse(bytes.fromhex(_SCAN_PUB_HEX))
    spend_pub = ec.PublicKey.parse(bytes.fromhex(_SPEND_PUB_HEX))

    psbt = PSBT.create_v2()

    inp = InputScope()
    inp.txid = bytes(32)
    inp.vout = 0
    inp.sequence = 0xFFFFFFFE
    # P2TR witness UTXO
    inp.witness_utxo = TransactionOutput(
        value=100_000, script_pubkey=Script(b"\x51\x20" + pub.xonly())
    )
    inp.taproot_bip32_derivations[pub] = (
        [],
        DerivationPath(fingerprint, parse_path("m/86h/1h/0h/0/0")),
    )
    psbt.add_input(inp)

    out = OutputScope()
    out.value = 99_000
    out.script_pubkey = None
    out.sp_data = SilentPaymentData(scan_pub, spend_pub)
    psbt.add_output(out)
    psbt.tx_modifiable_flags = 0

    return psbt.serialize()


def test_sp_signing_no_eligible_inputs_error(m5stickv):
    """P2TR-only inputs with SP outputs must produce a descriptive error at load time."""
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE

    wallet = _make_sp_wallet()
    raw = _build_sp_psbt_with_p2tr_input()

    with pytest.raises(ValueError, match="P2PKH, P2WPKH, or P2SH-P2WPKH"):
        PSBTSigner(wallet, raw, FORMAT_NONE)


def _build_sp_psbt_wrong_fingerprint():
    """Build PSBTv2 with bip32_derivation fingerprint that doesn't match wallet."""
    import sys

    sys.path.insert(0, "vendor/embit/src")
    from embit.bip32 import HDKey, parse_path
    from embit.bip39 import mnemonic_to_seed
    from embit.psbt import DerivationPath
    from embit.silent_payments import (
        SilentPaymentData,
        SilentPaymentsPSBT as PSBT,
        SPInputScope as InputScope,
        SPOutputScope as OutputScope,
    )
    from embit import ec
    from embit.script import p2wpkh, Script
    from embit.transaction import TransactionOutput

    seed = mnemonic_to_seed(TEST_MNEMONIC)
    root = HDKey.from_seed(seed)
    child = root.derive("m/84h/1h/0h/0/0")
    pub = child.get_public_key()

    scan_pub = ec.PublicKey.parse(bytes.fromhex(_SCAN_PUB_HEX))
    spend_pub = ec.PublicKey.parse(bytes.fromhex(_SPEND_PUB_HEX))

    psbt = PSBT.create_v2()

    inp = InputScope()
    inp.txid = bytes(32)
    inp.vout = 0
    inp.sequence = 0xFFFFFFFE
    inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2wpkh(pub))
    wrong_fp = b"\xde\xad\xbe\xef"
    inp.bip32_derivations[pub] = DerivationPath(
        wrong_fp, parse_path("m/84h/1h/0h/0/0")
    )
    psbt.add_input(inp)

    out = OutputScope()
    out.value = 99_000
    out.script_pubkey = Script(b"\x51\x20" + bytes(32))
    out.sp_data = SilentPaymentData(scan_pub, spend_pub)
    psbt.add_output(out)
    psbt.tx_modifiable_flags = 0

    return psbt.serialize()


def test_sp_signing_fingerprint_mismatch_error(m5stickv):
    """Wrong fingerprint in bip32_derivation must produce a descriptive error."""
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE

    wallet = _make_sp_wallet()
    raw = _build_sp_psbt_wrong_fingerprint()
    signer = PSBTSigner(wallet, raw, FORMAT_NONE)

    with pytest.raises(ValueError, match="fingerprint mismatch"):
        signer.sign()


def _build_sp_psbt_no_derivations():
    """Build PSBTv2 with P2WPKH input but no bip32_derivations."""
    import sys

    sys.path.insert(0, "vendor/embit/src")
    from embit.bip32 import HDKey
    from embit.bip39 import mnemonic_to_seed
    from embit.silent_payments import (
        SilentPaymentData,
        SilentPaymentsPSBT as PSBT,
        SPInputScope as InputScope,
        SPOutputScope as OutputScope,
    )
    from embit import ec
    from embit.script import p2wpkh, Script
    from embit.transaction import TransactionOutput

    seed = mnemonic_to_seed(TEST_MNEMONIC)
    root = HDKey.from_seed(seed)
    child = root.derive("m/84h/1h/0h/0/0")
    pub = child.get_public_key()

    scan_pub = ec.PublicKey.parse(bytes.fromhex(_SCAN_PUB_HEX))
    spend_pub = ec.PublicKey.parse(bytes.fromhex(_SPEND_PUB_HEX))

    psbt = PSBT.create_v2()

    inp = InputScope()
    inp.txid = bytes(32)
    inp.vout = 0
    inp.sequence = 0xFFFFFFFE
    inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2wpkh(pub))
    # Deliberately omit bip32_derivations
    psbt.add_input(inp)

    out = OutputScope()
    out.value = 99_000
    out.script_pubkey = Script(b"\x51\x20" + bytes(32))
    out.sp_data = SilentPaymentData(scan_pub, spend_pub)
    psbt.add_output(out)
    psbt.tx_modifiable_flags = 0

    return psbt.serialize()


def test_sp_signing_no_derivations_error(m5stickv):
    """Missing bip32_derivations on eligible input must produce a descriptive error."""
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE

    wallet = _make_sp_wallet()
    raw = _build_sp_psbt_no_derivations()
    signer = PSBTSigner(wallet, raw, FORMAT_NONE)

    with pytest.raises(ValueError, match="no BIP-32 derivations"):
        signer.sign()


def test_psbt_error_message_propagates_details(m5stickv):
    """ValueError raised by PSBTSigner must include the original error details."""
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE

    with pytest.raises(ValueError, match="invalid PSBT:"):
        PSBTSigner(_make_sp_wallet(), b"not a psbt", FORMAT_NONE)
