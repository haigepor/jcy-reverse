import sys, time
import frida
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
session = dev.attach('囧次元')
script = session.create_script(open('research/tmp_hook_dlsym.js', encoding='utf-8').read())
out = open('research/tmp_hook_log.txt', 'w', encoding='utf-8')
def on_msg(m, data):
    if m['type'] == 'send': line = m['payload']
    elif m['type'] == 'error': line = '[err] ' + m.get('description','')
    else: line = str(m)
    print(line); out.write(line + '\n'); out.flush()
script.on('message', on_msg)
script.load()
print('--- loaded, waiting 20s ---')
time.sleep(20)
