/* Worker-owned v86 and guest filesystem. */
'use strict';
importScripts(new URL('../terminal/v86/libv86.js',self.location.href));
const MAX_FILE=128*1024*1024,MAX_QUEUE=64,trashOrigins=new Map();
const NINE_P_MAX=1024*1024,NINE_P_QUEUE=32;
let vm=null,ready=false,closed=false,queued=0,chain=Promise.resolve(),serial='',serialTimer=null,outgoingFrames=0;
function path(value){const parts=[];for(const part of String(value).replace(/^\/home\/guest(?=\/|$)/,'').split('/')){if(!part||part==='.')continue;if(part==='..')parts.pop();else{if(part.includes('\0'))throw Error('Invalid filename.');parts.push(part);}}return '/'+parts.join('/');}
function fs(){if(!ready||!vm?.fs9p)throw Error('Guest home is still starting.');return vm.fs9p;}
function stat(value){const f=fs(),p=path(value),info=f.SearchPath(p);if(info.id<0)throw Error('File or folder not found: '+p);const node=f.GetInode(info.id);return {...info,path:p,size:node.size,mode:node.mode,dir:f.IsDirectory(info.id)};}
async function execute(method,args){
 const f=fs();
 if(method==='pauseGuest')return vm.stop();
 if(method==='resumeGuest')return vm.run();
 if(method==='stat')return stat(args[0]);
 if(method==='list'){const s=stat(args[0]);if(!s.dir)throw Error('Choose a folder.');return f.GetChildren(s.id).map(name=>({...stat(s.path+'/'+name),name})).sort((a,b)=>Number(b.dir)-Number(a.dir)||a.name.localeCompare(b.name));}
 if(method==='mkdir'){const p=path(args[0]),s=f.SearchPath(p);if(s.id>=0)throw Error('That name already exists.');if(s.parentid<0)throw Error('Parent folder does not exist.');f.CreateDirectory(p.split('/').pop(),s.parentid);return;}
 if(method==='read'){const s=stat(args[0]);if(s.dir)throw Error('Choose a file.');if(s.size===0)return new Uint8Array(0);return vm.read_file(s.path);}
 if(method==='write'){const p=path(args[0]),bytes=typeof args[1]==='string'?new TextEncoder().encode(args[1]):args[1];if(!(bytes instanceof Uint8Array)||bytes.length>MAX_FILE)throw Error('Files are limited to 128 MB in this desktop.');const info=f.SearchPath(p);if(info.id>=0){if(f.IsDirectory(info.id))throw Error('That name is a folder.');await f.ChangeSize(info.id,bytes.length);if(bytes.length)await f.Write(info.id,0,bytes.length,bytes);}else{if(info.parentid<0)throw Error('Parent folder does not exist.');await vm.create_file(p,bytes);}return;}
 if(method==='move'){const s=stat(args[0]),dest=path(args[1]),d=f.SearchPath(dest);if(s.path==='/'||dest==='/'||d.id>=0||d.parentid<0)throw Error('Choose an unused destination in an existing folder.');if(await f.Rename(s.parentid,s.path.split('/').pop(),d.parentid,dest.split('/').pop())<0)throw Error('Could not move Linux file.');return;}
 if(method==='remove'){const s=stat(args[0]);if(s.path==='/')throw Error('Cannot remove Linux home.');if(f.IsDirectory(s.id)&&f.GetChildren(s.id).length)throw Error('Folder must be empty before deleting.');if(f.Unlink(s.parentid,s.path.split('/').pop())<0)throw Error('Could not remove Linux file.');return;}
 if(method==='trash'){const s=stat(args[0]);if(s.path==='/'||s.path==='/Trash')throw Error('This folder cannot be removed.');if(s.path.startsWith('/Trash/')){if(f.Unlink(s.parentid,s.path.split('/').pop())<0)throw Error('Folder must be empty before deleting permanently.');trashOrigins.delete(s.path);}else{const target='/Trash/'+Date.now()+'-'+s.path.split('/').pop();if(await f.Rename(s.parentid,s.path.split('/').pop(),stat('/Trash').id,target.split('/').pop())<0)throw Error('Could not move item to Trash.');trashOrigins.set(target,s.path);}return;}
 if(method==='restore'){const s=stat(args[0]),dest=trashOrigins.get(s.path);if(!dest)throw Error('Original location is unknown.');const d=f.SearchPath(dest);if(d.id>=0)throw Error('An item already exists at the original location.');if(d.parentid<0)throw Error('Original folder no longer exists.');if(await f.Rename(s.parentid,s.path.split('/').pop(),d.parentid,dest.split('/').pop())<0)throw Error('Restore failed.');trashOrigins.delete(s.path);return;}
 throw Error('Unknown guest operation.');
}
function fail(error){postMessage({type:'fatal',message:String(error?.message||error)});}
function accountFilesystem(port){
 const pending=new Map();
 const tag=packet=>packet[5]|(packet[6]<<8);
 const packetValid=packet=>packet instanceof Uint8Array&&packet.length>=7&&packet.length<=NINE_P_MAX&&
  new DataView(packet.buffer,packet.byteOffset,packet.byteLength).getUint32(0,true)===packet.length;
 port.onmessage=({data})=>{
  if(!packetValid(data)){fail('Invalid account filesystem response.');return;}
  const id=tag(data),reply=pending.get(id);
  if(!reply){fail('Account filesystem response has no pending request.');return;}
  pending.delete(id);
  reply(data);
 };
 port.onmessageerror=()=>fail('Account filesystem message could not be read.');
 return {handle9p(packet,reply){
  if(!packetValid(packet)||pending.size>=NINE_P_QUEUE||pending.has(tag(packet))){
   fail('Invalid or excessive account filesystem requests.');return;
  }
  pending.set(tag(packet),reply);
  port.postMessage(packet,[packet.buffer]);
 }};
}
function flush(){serialTimer=null;if(serial){const text=serial;serial='';postMessage({type:'serial',text});}}
onmessage=({data})=>{
 if(closed||!data||typeof data!=='object')return;
 if(data.type==='start'){
  if(vm){fail('Guest already started.');return;}
  try{
   const account=data.accountPort instanceof MessagePort;
   const options=account?{...data.options,filesystem:accountFilesystem(data.accountPort)}:data.options;
   vm=new V86(options);vm.bus.register('net0-send',frame=>{if(frame instanceof Uint8Array&&frame.length>=14&&frame.length<=1518&&outgoingFrames<64){outgoingFrames++;postMessage({type:'frame',frame});}},null);
   vm.add_listener('serial0-output-byte',byte=>{serial+=String.fromCharCode(byte);if(serial.length>=65536)flush();else if(serialTimer===null)serialTimer=setTimeout(flush,5);});
   vm.add_listener('download-error',event=>postMessage({type:'download-error',event:{file_name:String(event.file_name||'')}}));
   vm.add_listener('emulator-ready',()=>{try{if(!account){const root=vm.fs9p.GetInode(0);root.uid=1000;root.gid=1000;root.mode=0o40777;}ready=true;postMessage({type:'ready'});}catch(e){fail(e);}});
  }catch(e){fail(e);}return;
 }
 if(data.type==='serial'){if(vm&&typeof data.text==='string'&&data.text.length<=65536)vm.serial0_send(data.text);return;}
 if(data.type==='frame'){const b=data.frame;try{if(vm&&b instanceof Uint8Array&&b.length>=14&&b.length<=1518)vm.bus.send('net0-receive',b);}finally{postMessage({type:'frame-received'});}return;}
 if(data.type==='frame-ack'){if(outgoingFrames>0)outgoingFrames--;return;}
 if(data.type==='rpc'){
  if(!Number.isSafeInteger(data.id)||typeof data.method!=='string'||!Array.isArray(data.args))return;
  if(queued>=MAX_QUEUE){postMessage({type:'reply',id:data.id,ok:false,error:'Guest request queue is full.'});return;}
  queued++;chain=chain.then(async()=>{try{const value=await execute(data.method,data.args);if(!closed)postMessage({type:'reply',id:data.id,ok:true,value});}catch(error){if(!closed)postMessage({type:'reply',id:data.id,ok:false,error:String(error?.message||error)});}finally{queued--;}});return;
 }
 if(data.type==='stop'){closed=true;clearTimeout(serialTimer);Promise.resolve(vm?.destroy()).catch(()=>{}).finally(()=>close());}
};
