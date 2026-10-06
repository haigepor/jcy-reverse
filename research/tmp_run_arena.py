import frida, time
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
session = dev.attach(7322)
script = session.create_script(open('research/tmp_arena.js', encoding='utf-8').read())
def on_msg(m, d):
    if m['type'] != 'send': print('[ERR]', str(m)[:200]); return
    print(m['payload'])
script.on('message', on_msg)
script.load()
time.sleep(5)
