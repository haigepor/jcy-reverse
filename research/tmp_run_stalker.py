import frida, time, json
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
session = dev.attach(7322)
script = session.create_script(open('research/tmp_stalker.js', encoding='utf-8').read())
f = open('research/tmp_stalker_log.txt', 'w', encoding='utf-8')
def on_msg(m, d):
    if m['type'] != 'send':
        print('[ERR]', m); return
    p = m['payload']
    print(p[:400])
    f.write(p + '\n'); f.flush()
script.on('message', on_msg)
script.load()
print('--- waiting 90s for app traffic ---'); time.sleep(90)
