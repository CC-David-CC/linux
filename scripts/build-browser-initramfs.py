import argparse, hashlib, json, os, stat, gzip, subprocess
from pathlib import Path
project=Path(__file__).resolve().parent.parent
guest=project.parent.parent/'downloads/desktop-v86-source/debian-root'
if not guest.is_dir():guest=project.parent.parent.parent/'downloads/desktop-v86-source/debian-root'
parser=argparse.ArgumentParser(description='Build a separate CDMUX/2 guest with nano; never overwrite a live image.')
parser.add_argument('--guest-root',type=Path,default=guest,help='Prepared i386 Debian build root')
parser.add_argument('--python-uv',type=Path,help='Pinned static i686 uv binary; include Python and uv')
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--work-dir',type=Path,required=True)
args=parser.parse_args();guest=args.guest_root.absolute();root=args.work_dir.absolute();out=args.output.absolute()
for p in [root,out]:
    if p.exists() or p.is_symlink() or not p.is_relative_to(project/'.build') or any(a.is_symlink() for a in p.parents):raise ValueError('Choose new real paths under active-system/.build')
root.mkdir(parents=True);out.parent.mkdir(parents=True,exist_ok=True)
for d in ('bin','dev','proc','sys','tmp','root','lib','etc','sbin','home/guest','usr/bin'):(root/d).mkdir(parents=True, exist_ok=True)
os.chmod(root/'tmp',0o1777)
os.chmod(root/'home/guest',0o700)
import shutil
shutil.copy2(guest/'bin/busybox',root/'bin/busybox')
for name in ('ld-linux.so.2','libc.so.6','libresolv.so.2'):
    shutil.copy2(guest/'usr/lib/i386-linux-gnu'/name,root/'lib'/name)
applets=subprocess.check_output([guest/'bin/busybox','--list'],text=True).splitlines()
for applet in applets:
    link=root/'bin'/applet
    if link.is_symlink() or link.exists(): link.unlink()
    link.symlink_to('busybox')
# Ping is the only fixed privileged command; the interactive shell remains UID 1000.
(root/'bin/ping').unlink(missing_ok=True)
subprocess.run(['as','--32','-o',str(root/'ping.o'),str(project/'scripts/guest-ping.S')],check=True)
subprocess.run(['ld','-m','elf_i386','-o',str(root/'bin/ping'),str(root/'ping.o')],check=True)
(root/'ping.o').unlink()
(root/'bin/ping').chmod(0o4755)
(root/'etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\nguest:x:1000:1000:Browser guest:/home/guest:/bin/sh\n')
(root/'etc/group').write_text('root:x:0:\nguest:x:1000:\n')
subprocess.run(['as','--32','-o',str(root/'drop.o'),str(project/'scripts/guest-drop-privilege.S')],check=True)
subprocess.run(['ld','-m','elf_i386','-o',str(root/'sbin/drop-to-guest'),str(root/'drop.o')],check=True)
(root/'drop.o').unlink()
# Compile with the existing isolated i386 toolchain and matching guest libc.
# Temporary source/artifacts are removed from the downloaded build root.
build_dir=Path(subprocess.check_output(['sudo','-n','mktemp','-d',str(guest/'tmp/codi-terminal-XXXXXX')],text=True).strip())
try:
    output='/'+str(build_dir.relative_to(guest))+'/terminal-mux'
    subprocess.run(['sudo','-n','chroot',str(guest),'/usr/bin/gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-x','c','-o',output,'-'],input=(project/'scripts/guest-terminal-mux.c').read_bytes(),check=True)
    raw=subprocess.check_output(['sudo','-n','cat',str(build_dir/'terminal-mux')])
    (root/'sbin/terminal-mux').write_bytes(raw);(root/'sbin/terminal-mux').chmod(0o755)
finally:
    subprocess.run(['sudo','-n','rm','-rf','--',str(build_dir)],check=True)

# Include the matching kernel's 9p and VirtIO modules in the early filesystem.
module_root=guest/'lib/modules/6.1.0-54-686'
deps={}
for line in (module_root/'modules.dep').read_text().splitlines():
    name, children=line.split(':',1)
    deps[name]=children.split()
order=[]
def include(name):
    if name in order:return
    for child in deps[name]:include(child)
    order.append(name)
for suffix in ('/virtio_pci.ko','/9pnet_virtio.ko','/9p.ko','/virtio_net.ko'):
    include(next(name for name in deps if name.endswith(suffix)))
(root/'modules').mkdir(exist_ok=True)
for name in order:shutil.copy2(module_root/name,root/'modules'/Path(name).name)
(root/'modules/load-order').write_text(''.join(Path(name).name+'\n' for name in order))
shutil.copy2(project/'scripts/guest-init.sh',root/'init')
(root/'init').chmod(0o755)
# Small native guest tools and their exact matching i386 dependencies.
shutil.copyfile(guest/'usr/bin/nano',root/'usr/bin/nano');(root/'usr/bin/nano').chmod(0o755)
for name in ('libncursesw.so.6','libtinfo.so.6'):
    shutil.copyfile(guest/'usr/lib/i386-linux-gnu'/name,root/'lib'/name)
for name in ('xterm-256color','xterm','vt100'):
    source=guest/'usr/lib/terminfo'/name[0]/name
    target=root/'usr/share/terminfo'/name[0]/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
(root/'etc/nanorc').write_text('set tabsize 4\n')
# Optional i386 CPython and matching Debian libraries. This extends the existing
# BusyBox guest; it does not turn the initramfs into a Debian installation.
if args.python_uv:
    uv=args.python_uv.resolve()
    if hashlib.sha256(uv.read_bytes()).hexdigest() != '55ce1c6f70117424da38e3da6ca3f01adf8c14b080dd7337d1a9e6712b456fa5':
        raise ValueError('Unexpected uv binary; supply the reviewed 0.13.6 i686 build')
    shutil.copyfile(guest/'usr/bin/python3.11',root/'usr/bin/python3.11')
    (root/'usr/bin/python3.11').chmod(0o755)
    (root/'usr/bin/python3').symlink_to('python3.11')
    (root/'usr/lib').mkdir(exist_ok=True)
    shutil.copytree(guest/'usr/lib/python3.11',root/'usr/lib/python3.11',symlinks=True,ignore=shutil.ignore_patterns('__pycache__','*.pyc','test','tests'))
    for lib in ('libbz2.so.1.0','libcrypt.so.1','libcrypto.so.3','libdb-5.3.so','libexpat.so.1','libffi.so.8','libgssapi_krb5.so.2','libk5crypto.so.3','libkeyutils.so.1','libkrb5.so.3','libkrb5support.so.0','liblzma.so.5','libm.so.6','libnsl.so.2','libpanelw.so.6','libreadline.so.8','libsqlite3.so.0','libssl.so.3','libtirpc.so.3','libuuid.so.1','libz.so.1','libcom_err.so.2'):
        shutil.copyfile(guest/'usr/lib/i386-linux-gnu'/lib,root/'lib'/lib)
    shutil.copyfile(uv,root/'usr/bin/uv');(root/'usr/bin/uv').chmod(0o755)

licenses=root/'licenses';licenses.mkdir()
for package in ('nano','libc6','libncursesw6','libtinfo6','ncurses-base'):
    source=guest/'usr/share/doc'/package/'copyright'
    shutil.copyfile(source,licenses/(package+'.copyright'))
if args.python_uv:
    # Preserve upstream and Debian distribution notices alongside the image.
    for package in ('python3.11','python3.11-minimal','libpython3.11-stdlib','libpython3.11-minimal','libssl3','libsqlite3-0','libbz2-1.0','libffi8','liblzma5','libreadline8','zlib1g','libexpat1','libgssapi-krb5-2','libkrb5-3','libnsl2','libtirpc3','libuuid1','libcrypt1','libdb5.3'):
        source=guest/'usr/share/doc'/package/'copyright'
        if source.is_file():shutil.copyfile(source,licenses/(package+'.copyright'))
    for name in ('uv-MIT.txt','uv-APACHE.txt'):
        shutil.copyfile(project/'scripts/notices'/name,licenses/name)
for name in ('GPL-2','GPL-3','LGPL-2.1'):
    shutil.copyfile(guest/'usr/share/common-licenses'/name,licenses/name)
versions=subprocess.check_output(['sudo','-n','chroot',str(guest),'/usr/bin/dpkg-query','-W','-f=${Package} ${Version} ${Architecture}\n','nano','libc6','libncursesw6','libtinfo6','ncurses-base'],text=True)
(licenses/'package-versions.txt').write_text(versions)
entries=[]
# Add files and symlinks from tree.
for p in sorted(root.rglob('*')):
    rel='./' + str(p.relative_to(root))
    st=p.lstat()
    if stat.S_ISDIR(st.st_mode): data=b''; mode=stat.S_IFDIR | (st.st_mode & 0o777); nlink=2
    elif stat.S_ISLNK(st.st_mode): data=os.readlink(p).encode(); mode=stat.S_IFLNK | (st.st_mode & 0o777); nlink=1
    elif stat.S_ISREG(st.st_mode): data=p.read_bytes(); mode=stat.S_IFREG | (st.st_mode & 0o7777); nlink=1
    else: continue
    entries.append((rel,data,mode,nlink,0))
entries.append(('./dev/console',b'',stat.S_IFCHR|0o600,1,(5<<8)|1))
entries.append(('./dev/null',b'',stat.S_IFCHR|0o666,1,(1<<8)|3))
with out.open('wb') as raw:
  with gzip.GzipFile(fileobj=raw,mode='wb',compresslevel=9,mtime=0) as f:
    ino=1
    for name,data,mode,nlink,rdev in entries:
      nameb=name.encode()+b'\0'; fields=[ino,mode,0,0,nlink,0,len(data),0,0,os.major(rdev),os.minor(rdev),len(nameb),0]
      f.write(b'070701'+b''.join(f'{x:08x}'.encode() for x in fields)+nameb)
      namepad=(-(110+len(nameb)))%4
      if namepad:f.write(b'\0'*namepad)
      f.write(data)
      if len(data)%4:f.write(b'\0'*(4-len(data)%4))
      ino+=1
    nameb=b'TRAILER!!!\0';fields=[0,0,0,0,1,0,0,0,0,0,0,len(nameb),0]
    f.write(b'070701'+b''.join(f'{x:08x}'.encode() for x in fields)+nameb)
    namepad=(-(110+len(nameb)))%4
    if namepad:f.write(b'\0'*namepad)

print(json.dumps({'status':'PASS','output':str(out),'protocol':'CDMUX/2','bytes':out.stat().st_size,'sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'nanoIncluded':True,'pythonUvIncluded':bool(args.python_uv),'legacyImageChanged':False},indent=2))
