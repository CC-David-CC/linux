#!/usr/bin/env python3
"""Exercise the candidate Worker client and filesystem against real v86 Linux."""
import functools,http.server,importlib.util,threading
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];spec=importlib.util.spec_from_file_location('driver',ROOT/'scripts/touch-preview-check.py');d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
class Quiet(http.server.SimpleHTTPRequestHandler):
 def log_message(self,*args):pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Quiet,directory=str(ROOT)));thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();sid=None
def js(code,args=[]):return d.call('/session/'+sid+'/execute/sync',{'script':code,'args':args})
def task(code,args=[]):
 r=d.call('/session/'+sid+'/execute/async',{'script':'const a=Array.from(arguments),done=a.pop();(async()=>{'+code+'})().then(v=>done({ok:true,value:v}),e=>done({ok:false,error:String(e)}));','args':args});assert r['ok'],r;return r['value']
try:
 sid=d.call('/session',{'capabilities':{'alwaysMatch':{'browserName':'chrome','goog:chromeOptions':{'binary':'/snap/chromium/current/usr/lib/chromium-browser/chrome','args':['--headless=new','--no-sandbox','--disable-dev-shm-usage']}}}})['sessionId'];d.call('/session/'+sid+'/timeouts',{'script':60000});d.call('/session/'+sid+'/url',{'url':'http://127.0.0.1:'+str(server.server_port)+'/scripts/fixtures/guest-worker-client.html'})
 def ready():
  fatal=js('return fatal;');assert not fatal,fatal
  return js('return ready&&shell.includes("$");')
 d.wait(ready,120);print('PASS real Linux and independent terminal transport',flush=True)
 assert task('await vm.request("mkdir","/Trash");await vm.request("mkdir","/Documents");await vm.request("write","/Documents/demo.txt","hello");return true;')
 assert task('const s=await vm.request("stat","/Documents/demo.txt"),l=await vm.request("list","/Documents");return !s.dir&&s.size===5&&l.length===1&&l[0].name==="demo.txt";');print('PASS mkdir, write, stat and list',flush=True)
 js('command("printf \\\"\\nWORKER_CLIENT_READ=\\\"; cat /home/guest/Documents/demo.txt; printf \\\"\\nWORKER_CLIENT_END\\n\\\"\\r");');d.wait(lambda:js('return shell.includes("WORKER_CLIENT_READ=hello")&&shell.includes("WORKER_CLIENT_END");'),30)
 js('command("printf shell-data > /home/guest/Documents/shell.txt; printf \\\"\\nWORKER_CLIENT_WRITE_END\\n\\\"\\r");');d.wait(lambda:js('return shell.includes("WORKER_CLIENT_WRITE_END");'),30);assert task('return new TextDecoder().decode(await vm.read_file("/Documents/shell.txt"));')=='shell-data';print('PASS bidirectional file sharing with the shell',flush=True)
 assert task('await vm.request("trash","/Documents/demo.txt");const items=await vm.request("list","/Trash");if(items.length!==1)return false;await vm.request("restore",items[0].path);return new TextDecoder().decode(await vm.read_file("/Documents/demo.txt"))==="hello";');print('PASS trash and restore',flush=True)
 assert task('const p=vm.request("stat","/Documents/demo.txt");vm.close();try{await p;return false;}catch(e){return e.message.includes("closed");}');assert task('try{await vm.request("stat","/");return false;}catch(e){return e.message.includes("closed");}');print('PASS close rejects in-flight and future work',flush=True)
 assert task('''const Native=window.Worker,{GuestWorkerClient}=await import('/assets/desktop/guest-worker-client.mjs');let fake,fatal=0;window.Worker=class{constructor(){fake=this;}postMessage(x){this.last=x;}terminate(){this.terminated=true;}};try{const c=new GuestWorkerClient('/fake',{timeoutMs:1000,onFatal:()=>fatal++}),p=c.request('stat','/').catch(e=>e.message);const id=fake.last.id;const result=await p;fake.onmessage({data:{type:'reply',id,ok:true,value:'late'}});if(!result.includes('may have completed'))return false;let pending=[];for(let i=0;i<64;i++)pending.push(c.request('stat','/').catch(e=>e.message));let limit;try{await c.request('stat','/');}catch(e){limit=e.message;}fake.onerror({message:'test failure'});const results=await Promise.all(pending);return limit.includes('queue is full')&&fatal===1&&fake.terminated&&results.every(x=>x.includes('closed'));}finally{window.Worker=Native;}''');print('PASS bounded requests, timeout uncertainty, late replies and fatal cleanup',flush=True)
 assert task('''const Native=window.Worker,{GuestWorkerClient}=await import('/assets/desktop/guest-worker-client.mjs');let fake;window.Worker=class{constructor(){fake=this;this.messages=[];}postMessage(x){this.messages.push(x);}terminate(){}};try{const c=new GuestWorkerClient('/fake'),f=new Uint8Array(42);for(let i=0;i<70;i++)c.bus.send('net0-receive',f);if(fake.messages.filter(x=>x.type==='frame').length!==64)return false;fake.onmessage({data:{type:'frame-received'}});c.bus.send('net0-receive',f);if(fake.messages.filter(x=>x.type==='frame').length!==65)return false;let seen=0;c.bus.register('net0-send',()=>seen++,null);fake.onmessage({data:{type:'frame',frame:f}});const ack=fake.messages.at(-1).type==='frame-ack';c.close();return seen===1&&ack;}finally{window.Worker=Native;}''');print('PASS Ethernet receive queue is bounded and acknowledgements restore capacity',flush=True)
finally:
 if sid:d.call('/session/'+sid,method='DELETE')
 server.shutdown();server.server_close();thread.join(timeout=3)
