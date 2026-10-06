import ast

p = 'research/toolchain/emu_unwind.py'
s = open(p, encoding='utf-8', newline='').read()

blk = '''    if args.then_decrypt and body:
        try:
            pl2 = {"action": "api_decrypt", "payload": {"data": body, "path": args.path}}
            for i in range(10):
                pl2['n%d' % i] = 'N0ISE%02dXYZABCD' % i
            enc2 = ch_encrypt(json.dumps(pl2, separators=(',', ':')).encode())
            inp2 = e.alloc(len(enc2) + 1)
            e.wr(inp2, enc2.encode() + b"\\x00")
            PHASE[0] = 'api-decrypt-2nd'
            out2 = e.call(DEV_BASE + CALL_OFF, (inp2, CB_ADDR), timeout=600_000_000)
            log('[*] 2nd(api_decrypt) x0=0x%x, captures=%d' % (out2, len(CAPTURES)))
            if out2 and out2 > 0x1000:
                s2 = rd(e.uc, out2, 16384)
                if s2:
                    s2 = s2.split(b'\\x00')[0]
                    log('[*] 2nd 返回串(%dB): %r' % (len(s2), s2[:600]))
                    open('research/tmp_then_dec_ret.bin', 'wb').write(s2)
        except unicorn.unicorn.UcError as ex:
            pc = e.uc.reg_read(UC_ARM64_REG_PC)
            lr = e.uc.reg_read(UC_ARM64_REG_LR)
            log('[!!] 2nd crash %s PC_off=0x%x LR_off=0x%x' % (ex, pc - DEV_BASE, lr - DEV_BASE))
            log('[*] 最近桩: %s' % e.logs[-8:])
'''

assert blk in s, 'block not found'
s = s.replace(blk, '')  # 从 except 与 finally 之间摘除

anchor = "\n\nif __name__ == '__main__':\n    main()"
assert anchor in s
# 重新缩进: 块原本在 main() 内 4 空格层级, 放回 main 尾部(finally 套件之后)保持 4 空格
s = s.replace(anchor, '\n' + blk + anchor)
open(p, 'w', encoding='utf-8', newline='').write(s)
ast.parse(open(p, encoding='utf-8').read())
print('moved + syntax ok')
