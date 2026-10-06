import frida
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
session = dev.attach(7322)
script = session.create_script("""
const mods = Process.enumerateModules();
send('total modules: ' + mods.length);
const interesting = mods.filter(m => /app|core|lua|loader|flutter|plt/i.test(m.name));
interesting.forEach(m => send(m.name + ' base=' + m.base + ' size=' + m.size));
// also ranges: look for big anonymous RX regions (manual-loaded ELF)
const ranges = Process.enumerateRanges('r-x');
const big = ranges.filter(r => r.size > 0x400000 && r.file === undefined);
send('anon RX big regions: ' + big.length);
big.slice(0,10).forEach(r => send('  ' + r.base + ' size=' + r.size));
""")
def on_msg(m, d):
    print(m.get('payload') or m)
script.on('message', on_msg)
script.load()
import time; time.sleep(3)
