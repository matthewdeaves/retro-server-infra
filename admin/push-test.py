#!/usr/bin/env python3
"""Prove encrypt_push() against RFC 8291's own worked example. Run by bin/check.

There is no engine to bench this against and no browser in the loop, so the
one external fact worth checking against is the standard itself. The test
vector -- receiver key, sender key, salt, auth secret and the exact encrypted
body -- is Section 5 of RFC 8291, fetched from the RFC text and reproduced
here verbatim rather than re-derived, so a slip in re-deriving it cannot hide
a slip in the code.

as_key and salt are injectable in encrypt_push() ONLY for this: real callers
never pass them, because reusing either leaks the plaintext.
"""
import importlib.util, os, sys, tempfile

MODULE = sys.argv[1] if len(sys.argv) > 1 else "admin/retro-admin.py"

sys.dont_write_bytecode = True
STATE = tempfile.mkdtemp(prefix="pushtest-")
os.environ["STATE_DIRECTORY"] = STATE
spec = importlib.util.spec_from_file_location("ra", MODULE)
ra = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ra)

from cryptography.hazmat.primitives.asymmetric import ec

# RFC 8291 section 5, verbatim.
UA_PUB  = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
AS_PRIV = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
AUTH    = "BTBZMqHH6r4Tts7J_aSIgg"
SALT    = "DGv6ra1nlYgDCS1FRnbzlw"
PLAIN   = b"When I grow up, I want to be a watermelon"
WANT    = ("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml"
           "mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT"
           "pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN")

fails = []
def want(label, got, expected):
    ok = got == expected
    print("  %-52s %s" % (label, "ok" if ok else "FAIL  got %r want %r"
                          % (got, expected)))
    if not ok:
        fails.append(label)

as_priv_int = int.from_bytes(ra._b64u_decode(AS_PRIV), "big")
as_key = ec.derive_private_key(as_priv_int, ec.SECP256R1())

got = ra._b64u(ra.encrypt_push(UA_PUB, AUTH, PLAIN, salt=ra._b64u_decode(SALT),
                               as_key=as_key))
want("reproduces RFC 8291 section 5 exactly", got, WANT)

# The one thing a byte-exact match on a fixed salt cannot show: two calls
# with fresh salt must not collide, or the same key material leaks.
r1 = ra.encrypt_push(UA_PUB, AUTH, b"one")
r2 = ra.encrypt_push(UA_PUB, AUTH, b"two")
want("fresh calls use fresh salt", r1[:16] != r2[:16], True)

print()
print("round trip with FRESH keys, decrypted as the receiving browser would.")
print("A match on the RFC's fixed numbers proves the wire format. This proves")
print("the maths generalises, and would catch a bug tied to that one curve")
print("point that the fixed vector happens not to exercise.")
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
from cryptography.hazmat.primitives import serialization as _ser

ua_key = _ec.generate_private_key(_ec.SECP256R1())
ua_pub_bytes = ua_key.public_key().public_bytes(
    encoding=_ser.Encoding.X962, format=_ser.PublicFormat.UncompressedPoint)
ua_pub_b64 = ra._b64u(ua_pub_bytes)
auth_secret = os.urandom(16)
auth_b64 = ra._b64u(auth_secret)
plaintext = b"Half-Life stopped answering. Last answered 03:14."

body = ra.encrypt_push(ua_pub_b64, auth_b64, plaintext)

salt = body[:16]
rs = int.from_bytes(body[16:20], "big")
idlen = body[20]
as_pub_bytes = body[21:21 + idlen]
ciphertext = body[21 + idlen:]

as_pub = _ec.EllipticCurvePublicKey.from_encoded_point(_ec.SECP256R1(), as_pub_bytes)
shared = ua_key.exchange(_ec.ECDH(), as_pub)
key_info = b"WebPush: info\x00" + ua_pub_bytes + as_pub_bytes
ikm = ra._hkdf(auth_secret, shared, key_info, 32)
cek = ra._hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
nonce = ra._hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)
recovered = _AESGCM(cek).decrypt(nonce, ciphertext, None)

want("record size header is the fixed 4096", rs, 4096)
want("decrypts to exactly the plaintext given",
     recovered[:-1], plaintext)
want("ends with the RFC 8188 delimiter", recovered[-1], 2)

print()
print("the VAPID JWT verifies against the box's own published public key")
auth_header, pub = ra.vapid_auth("https://fcm.googleapis.com/fcm/send/abc123")
scheme, creds = auth_header.split(" ", 1)
want("Authorization uses the vapid scheme", scheme, "vapid")
parts = dict(p.strip().split("=", 1) for p in creds.split(","))
want("t= and k= are both present", sorted(parts), ["k", "t"])
want("k= is the public key, not something else", parts["k"], pub)
head_b64, claims_b64, sig_b64 = parts["t"].split(".")
signing_input = ("%s.%s" % (head_b64, claims_b64)).encode()
sig = ra._b64u_decode(sig_b64)
r_int = int.from_bytes(sig[:32], "big")
s_int = int.from_bytes(sig[32:], "big")
from cryptography.hazmat.primitives.asymmetric import utils as _asym_utils
from cryptography.hazmat.primitives import hashes as _hashes
der = _asym_utils.encode_dss_signature(r_int, s_int)
pub_key = _ec.EllipticCurvePublicKey.from_encoded_point(
    _ec.SECP256R1(), ra._b64u_decode(pub))
try:
    pub_key.verify(der, signing_input, _ec.ECDSA(_hashes.SHA256()))
    verified = True
except Exception:
    verified = False
want("signature verifies against vapid_public_b64()", verified, True)
import json as _json
claims = _json.loads(ra._b64u_decode(claims_b64))
want("aud is the push service's origin, not the endpoint path",
     claims.get("aud"), "https://fcm.googleapis.com")

print("\nFAILED: %s" % ", ".join(fails) if fails else "\nall push cases passed")
sys.exit(1 if fails else 0)
