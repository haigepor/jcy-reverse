import ast

p = 'research/toolchain/emu_unwind.py'
lines = open(p, encoding='utf-8', newline='').readlines()

# 定位 rand_cb 中先前插入的读块, 整体替换为 返回点读取方案
start = end = None
for i, l in enumerate(lines):
    if "log('[RAND_bytes] buf=0x%x num=%d'" in l:
        start = i + 1
    if start is not None and "log('[RAND_K16] 读失败 %s'" in l:
        end = i
        break
assert start is not None and end is not None, (start, end)
new = (
    "        try:\r\n"
    "            if xs[1] == 16 and not RAND_K16:\r\n"
    "                _lr = uc.reg_read(UC_ARM64_REG_LR)\r\n"
    "                _buf, _n = xs[0], xs[1]\r\n"
    "                def _rand_ret(_uc, _a, _s, _u, _b=_buf, _l=_lr):\r\n"
    "                    try:\r\n"
    "                        _rb = rd(_uc, _b, 16)\r\n"
    "                        RAND_K16.append(_rb)\r\n"
    "                        log('[RAND_K16] %s (ret@0x%x)' % (_rb.hex(), _l - DEV_BASE))\r\n"
    "                    except Exception as _ex:\r\n"
    "                        log('[RAND_K16] 读失败 %s' % _ex)\r\n"
    "                    return False\r\n"
    "                e.uc.hook_add(UC_HOOK_CODE, _rand_ret, begin=_lr, end=_lr)\r\n"
    "        except Exception as _ex:\r\n"
    "            log('[RAND_K16] 挂钩失败 %s' % _ex)\r\n"
)
lines[start:end + 1] = [new]
open(p, 'w', encoding='utf-8', newline='').writelines(lines)
ast.parse(open(p, encoding='utf-8').read())
print('rand_cb patched')
