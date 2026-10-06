import frida
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
for p in dev.enumerate_processes():
    if 'udou' in p.name or '囧' in p.name or 'uoguo' in p.name:
        print(p.pid, p.name)
