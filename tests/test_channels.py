"""jcy_protocol 测试：双通道加解密与帧构造。

可两种方式运行：
    ./.venv/Scripts/python.exe tests/test_channels.py   # 独立运行，失败退出码非 0
    pytest tests                                        # 兼容 pytest

所有断言基于真机抓包向量，见 jcy_protocol/vectors.py。
"""

from __future__ import annotations

import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from jcy_protocol import (  # noqa: E402
    MON_IV,
    MON_KEY,
    SIG_IV,
    SIG_KEY,
    aes128cbc_decrypt,
    aes128cbc_encrypt,
    channel_decrypt,
    channel_encrypt,
    http_headers,
    monitor_frame,
    pkcs7_pad,
    pkcs7_unpad,
    signaling_decrypt_response,
    signaling_request,
)
from jcy_protocol.vectors import (  # noqa: E402
    EXPECTED_KEY_IV_LEN,
    MONITOR_ROUNDTRIP_PLAINTEXT,
    SIGNALING_RESPONSE_B64,
    SIGNALING_RESPONSE_CT_LEN,
    SIGNALING_RESPONSE_PLAINTEXT,
    SIGNALING_RESPONSE_PT_LEN,
)


def test_key_iv_lengths():
    assert len(MON_KEY) == EXPECTED_KEY_IV_LEN
    assert len(MON_IV) == EXPECTED_KEY_IV_LEN
    assert len(SIG_KEY) == EXPECTED_KEY_IV_LEN
    assert len(SIG_IV) == EXPECTED_KEY_IV_LEN


def test_pkcs7_roundtrip():
    for size in (0, 1, 15, 16, 17, 31, 32):
        data = bytes(range(size % 256)) * (size // 256 + 1)
        data = data[:size]
        assert pkcs7_unpad(pkcs7_pad(data)) == data


def test_pkcs7_rejects_invalid_padding():
    try:
        pkcs7_unpad(b"\x00" * 16)
    except ValueError:
        return
    raise AssertionError("非法填充应抛 ValueError")


def test_signaling_response_vector_decrypts():
    """核心断言：真机抓包密文必须解出预期明文。"""
    plaintext = signaling_decrypt_response(SIGNALING_RESPONSE_B64)
    assert plaintext == SIGNALING_RESPONSE_PLAINTEXT, plaintext

    ciphertext = base64.b64decode(SIGNALING_RESPONSE_B64)
    assert len(ciphertext) == SIGNALING_RESPONSE_CT_LEN
    assert len(plaintext) == SIGNALING_RESPONSE_PT_LEN


def test_signaling_response_is_valid_json():
    payload = json.loads(signaling_decrypt_response(SIGNALING_RESPONSE_B64))
    assert payload["action"] == "get_app_info"
    assert payload["code"] == 200
    assert payload["payload"]["address"] == "723da3db40"


def test_monitor_channel_roundtrip():
    ciphertext = aes128cbc_encrypt(MON_KEY, MON_IV, MONITOR_ROUNDTRIP_PLAINTEXT)
    assert aes128cbc_decrypt(MON_KEY, MON_IV, ciphertext) == MONITOR_ROUNDTRIP_PLAINTEXT


def test_channel_encrypt_decrypt_roundtrip():
    plaintext = b'{"hello":"world","n":1}'
    frame = channel_encrypt(plaintext, SIG_KEY, SIG_IV)
    assert isinstance(frame, str)
    assert channel_decrypt(frame, SIG_KEY, SIG_IV) == plaintext


def test_signaling_request_contains_action_and_params():
    frame = signaling_request("get_app_info", {"address": "723da3db40"}, filler_pairs=3)
    obj = json.loads(channel_decrypt(frame.decode(), SIG_KEY, SIG_IV))
    assert obj["action"] == "get_app_info"
    assert obj["address"] == "723da3db40"
    # 诱饵对：3 组随机键值 + action + address = 5
    assert len(obj) == 5


def test_monitor_frame_shape():
    frame = monitor_frame("ping", {"t": 1}, filler_pairs=2)
    obj = json.loads(channel_decrypt(frame, MON_KEY, MON_IV))
    assert obj["action"] == "ping"
    assert json.loads(obj["params"]) == {"t": 1}
    assert len(obj) == 4


def test_http_headers_dynamic_fields():
    headers = http_headers("TOKEN_VALUE")
    assert headers["authentication"] == "TOKEN_VALUE"
    assert headers["appid"] == "com.tudou.tool"
    assert headers["ts"].isdigit() and len(headers["ts"]) == 13
    assert headers["nonce"].isdigit() and len(headers["nonce"]) == 8


def _main() -> int:
    tests = [(name, obj) for name, obj in sorted(globals().items()) if name.startswith("test_") and callable(obj)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL  {name}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())
