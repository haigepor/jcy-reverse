# -*- coding: utf-8 -*-
"""Driver: per-range memory scan via frida gadget, fault tolerant."""
import frida, json, sys, time

NEEDLES = ["-----BEGIN RSA PRIVATE KEY", "-----BEGIN PRIVATE KEY", "-----BEGIN PUBLIC KEY",
           "-----BEGIN RSA PUBLIC KEY", "4150439554430529", '"nonce"', '"ts":17',
           "6MsfEg71", '"appid"', "raw_play_url"]

def get_session():
    d = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    return d.attach('Gadget'), d

def fresh_script():
    session, d = get_session()
    script = session.create_script(open('out/client/gg_memscan.js', encoding='utf-8').read())
    script.load()
    time.sleep(0.5)
    n = script.exports_sync.init(NEEDLES)
    return session, script, n

def main():
    session, script, nranges = fresh_script()
    print(f"ranges: {nranges}", flush=True)
    all_ks, all_pem = [], []
    fail_streak = 0
    i = 0
    while i < nranges:
        try:
            r = script.exports_sync.scanidx(i)
            fail_streak = 0
            for h in r['found']:
                if h['kind'] in (1, 2):
                    all_ks.append(h)
                elif h['kind'] >= 100:
                    all_pem.append(h)
        except Exception as e:
            fail_streak += 1
            print(f"[{i}] fault: {str(e)[:80]}", flush=True)
            if fail_streak >= 3:
                # recreate script and skip ahead
                try:
                    session, script, nranges = fresh_script()
                except Exception as e2:
                    print("recreate failed:", e2, flush=True)
                    time.sleep(2)
                fail_streak = 0
                i += 1
                continue
            continue  # retry same range? fault range will fault again -> bump
        i += 1
    print(f"ks hits: {len(all_ks)}, needle hits: {len(all_pem)}", flush=True)
    # dump everything
    out = []
    for h in all_ks[:300]:
        try:
            hx = script.exports_sync.dump(h['ptr'], h['len'])
        except Exception:
            hx = None
        out.append({'kind': h['kind'], 'addr': h['ptr'], 'hex': hx})
        print(f"KS kind={h['kind']} @ {h['ptr']} {str(hx)[:40]}", flush=True)
    json.dump(out, open('out/mem_ks_hits.json', 'w'))
    for j, h in enumerate(all_pem[:60]):
        try:
            hx = script.exports_sync.dump(h['ptr'], 2600)
            if hx:
                open(f"out/mem_needle_k{h['kind']}_{j}.hex", 'w').write(hx)
                print(f"NEEDLE kind={h['kind']} @ {h['ptr']} -> out/mem_needle_k{h['kind']}_{j}.hex", flush=True)
        except Exception:
            pass
    print('DONE', flush=True)

if __name__ == '__main__':
    main()
