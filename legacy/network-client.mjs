/** Same-origin guest wire. Signing keys and session tokens never enter the NIC. */
import {hash,signJws,inspectJws,verifyJws,sameKey,validateTimes,nowSeconds,requireThat} from '../network/crypto.mjs';
import {verifyIdentity,PROOF_TYPE as REQUEST_TYPE} from '../network/identity.mjs';
import {strictJson} from '../network/strict-json.mjs';
const GRANT_TYPE='codi-guest-network-identity+jwt',USE_TYPE='codi-guest-network-use+jws';
const fields=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===names.length&&names.every(n=>Object.hasOwn(value,n));
const nonce=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{43}$/.test(value);

export class GuestNetworkAdapter{
  constructor(emulator,config,{getSession,onStatus=()=>{}}){
    const api=config?.identity?.apiBase,authorization=config?.guestNetwork?.authorization;
    requireThat(config?.identity?.mode==='server'&&config.identity.issuer===location.origin,'Same-origin server identity required');
    requireThat(typeof api==='string'&&/^\/(?:[A-Za-z0-9_-]+\/)*api\/v1$/.test(api),'Canonical identity API required');
    this.base=api.slice(0,-7);this.path=this.base+'/guest-network';
    requireThat(config.guestNetwork.relayPath===this.path&&authorization?.version==='codi-guest-network-auth/1'&&authorization.clientPath===this.base+'/guest-access/client.mjs'&&/^[0-9a-f]{64}$/.test(authorization.policySHA256),'Pinned guest authorization metadata required');
    requireThat(emulator?.bus&&typeof getSession==='function'&&!emulator.network_adapter,'Independent guest network adapter required');
    this.bus=emulator.bus;this.config=config;this.getSession=getSession;this.onStatus=onStatus;this.policy=authorization.policySHA256;this.api=api+'/guest-network';
    this.url=new URL(this.path,location.origin);this.url.protocol=location.protocol==='https:'?'wss:':'ws:';
    this.queue=[];this.mac=null;this.socket=null;this.connecting=null;this.connectionController=null;this.controlled=true;this.destroyed=false;this.epoch=0;this.session=undefined;this.mode='disconnected';this.authRequested=false;this.pendingGrant=null;this.controller=null;this.retry=1000;this.timer=null;this.nextAuth=0;this.resetAck=false;
    this.bus.register('net0-send',frame=>this.send(frame),this);emulator.network_adapter=this;
    this.signinOnly=config.guestNetwork.previewPolicy?.version==='codi-guest-egress-policy/2'&&config.guestNetwork.previewPolicy.anonymousInternet==='deny';
    this.syncSession();
  }
  get localOnly(){return this.signinOnly&&this.getSession()?.public.kind!=='registered';}
  get linkReady(){return !this.destroyed&&(this.localOnly||this.socket?.readyState===WebSocket.OPEN);}
  standby(){
    ++this.epoch;clearTimeout(this.timer);this.timer=null;this.controller?.abort();this.connectionController?.abort();
    this.controller=null;this.authRequested=false;this.pendingGrant=null;this.queue=[];
    const socket=this.socket;this.socket=null;socket?.close();this.session=this.getSession();
    this.status('anonymous','Sign in for Linux Internet. Local Linux and browser peer apps remain available.');
  }
  status(mode,message=''){this.mode=mode;this.message=message;this.onStatus({mode,message});}
  control(value){if(this.controlled&&this.socket?.readyState===WebSocket.OPEN)this.socket.send(JSON.stringify(value));}
  reset(){
    ++this.epoch;this.controller?.abort();this.controller=null;this.authRequested=false;this.pendingGrant=null;this.status('anonymous');this.resetAck=true;
    this.control({type:'codi-guest-network-reset/1'});
  }
  syncSession(){
    const session=this.getSession();
    if(this.localOnly){if(this.session!==session||this.socket||this.connecting||this.mode!=='anonymous')this.standby();return;}
    if(session!==this.session){this.session=session;this.reset();this.nextAuth=0;}
    if(this.socket?.readyState!==WebSocket.OPEN){this.connect();return;}
    if(this.controlled&&this.socket?.readyState===WebSocket.OPEN&&session?.public.kind==='registered'&&this.mode!=='registered'&&!this.authRequested&&Date.now()>=this.nextAuth){
      this.authRequested=true;this.control({type:'codi-guest-network-begin/1'});
    }
  }
  send(frame){
    if(this.destroyed)return;
    const bytes=frame instanceof Uint8Array?frame:frame instanceof ArrayBuffer?new Uint8Array(frame):null;
    if(!bytes||bytes.length<14||bytes.length>1518)return;
    if(!(bytes[6]&1)&&bytes.subarray(6,12).some(v=>v!==0))this.mac=new Uint8Array(bytes.subarray(6,12));
    if(this.localOnly)return;
    if(this.socket?.readyState===WebSocket.OPEN){if(this.socket.bufferedAmount<65536)this.socket.send(bytes);}
    else{this.queue.push(new Uint8Array(bytes));if(this.queue.length>64)this.queue.shift();this.connect();}
  }
  announceLink(socket){
    if(!this.mac||this.destroyed||this.socket!==socket||socket.readyState!==WebSocket.OPEN)return;
    // Linux can retain its gateway neighbor while a replacement slirp wire has
    // forgotten Linux's MAC. Ordinary bounded ARP requests also work with older
    // binary relays that accept requests but do not forward ARP replies.
    for(const target of [1,3]){
      const frame=new Uint8Array(42);frame.fill(255,0,6);frame.set(this.mac,6);frame.set([8,6,0,1,8,0,6,4,0,1],12);frame.set(this.mac,22);frame.set([10,86,0,2],28);frame.set([10,86,0,target],38);
      if(socket.bufferedAmount<65536)socket.send(frame);
    }
  }
  async currentProtocol(signal){
    const response=await fetch(this.base+'/config.json',{credentials:'same-origin',mode:'same-origin',redirect:'error',cache:'no-store',signal});
    requireThat(response.ok,'Guest network configuration unavailable');
    const reader=response.body.getReader(),chunks=[];let length=0;
    try{while(true){const {done,value}=await reader.read();if(done)break;length+=value.length;requireThat(length<=65536,'Guest network configuration too large');chunks.push(value);}}
    catch(error){await reader.cancel().catch(()=>{});throw error;}
    const bytes=new Uint8Array(length);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
    const fresh=strictJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes),{maxBytes:65536}),identity=fresh?.identity,expected=this.config.identity;
    requireThat(fields(identity,['mode','apiBase','issuer','audience','authorityClass','authorityKeys'])&&['mode','apiBase','issuer','audience','authorityClass'].every(n=>identity[n]===expected[n])&&Array.isArray(identity.authorityKeys)&&identity.authorityKeys.length===expected.authorityKeys.length,'Guest issuer configuration changed');
    requireThat(identity.authorityKeys.every((entry,i)=>fields(entry,['kid','jwk'])&&fields(entry.jwk,['kty','crv','x','y'])&&entry.kid===expected.authorityKeys[i].kid&&sameKey(entry.jwk,expected.authorityKeys[i].jwk)),'Guest issuer keys changed');
    const network=fresh.guestNetwork;requireThat(network?.relayPath===this.path,'Guest relay path changed');
    if(Object.hasOwn(network,'authorization')){
      requireThat(fields(network.authorization,['version','policySHA256','clientPath'])&&network.authorization.version==='codi-guest-network-auth/1'&&network.authorization.policySHA256===this.policy&&network.authorization.clientPath===this.base+'/guest-access/client.mjs','Pinned guest authorization metadata changed');
      return true;
    }
    // Only an explicit, well-formed older protocol enables binary-only mode.
    // Errors, missing metadata and changed issuer/policy never imply a downgrade.
    requireThat(network.egress==='relay-host'&&typeof network.relayRevision==='string'&&/^[0-9a-f]{64}$/.test(network.relayRevision)&&network.previewPolicy?.version==='bounded-preview/1','Explicit legacy guest relay metadata required');
    return false;
  }
  async connect(){
    if(this.localOnly){this.standby();return;}
    if(this.destroyed||this.connecting||this.socket?.readyState===WebSocket.CONNECTING||this.socket?.readyState===WebSocket.OPEN)return;
    clearTimeout(this.timer);const controller=new AbortController();this.connectionController=controller;const deadline=setTimeout(()=>controller.abort(),10000);
    this.connecting=(async()=>{
      // Renew the browser's HttpOnly transport cookie without reloading Linux.
      const response=await fetch(this.base+'/',{credentials:'same-origin',mode:'same-origin',redirect:'error',cache:'no-store',signal:controller.signal});
      if(!response.ok)throw Error('Guest connection cookie could not be renewed');
      await response.body?.cancel();if(this.destroyed||this.localOnly)return;
      const controlled=await this.currentProtocol(controller.signal);if(this.destroyed||this.localOnly)return;this.controlled=controlled;
      const socket=new WebSocket(this.url);this.socket=socket;socket.binaryType='arraybuffer';let opened=0;
      socket.onopen=()=>{
        if(this.destroyed||this.socket!==socket){socket.close();return;}
        opened=performance.now();this.status('anonymous');this.session=undefined;this.syncSession();
        this.announceLink(socket);
        for(const frame of this.queue)if(socket.bufferedAmount<65536)socket.send(frame);this.queue=[];
      };
      socket.onmessage=event=>{
        if(this.destroyed||this.socket!==socket)return;
        if(event.data instanceof ArrayBuffer){
          if(event.data.byteLength>=14&&event.data.byteLength<=1518)this.bus.send('net0-receive',new Uint8Array(event.data));
          else socket.close(1008,'Invalid guest Ethernet');
        }else{
          if(!this.controlled){socket.close(1008,'Unexpected legacy guest control');return;}
          try{this.handle(JSON.parse(event.data));}catch(error){this.failAuthorization(error,this.epoch);}
        }
      };
      socket.onerror=()=>{};
      socket.onclose=()=>{
        if(this.socket!==socket)return;
        this.socket=null;++this.epoch;this.controller?.abort();this.controller=null;this.authRequested=false;this.pendingGrant=null;
        if(opened&&performance.now()-opened>5000)this.retry=1000;
        this.status('disconnected','Guest Internet disconnected; reconnecting.');this.reconnect();
      };
    })().catch(error=>{if(!this.destroyed&&!this.localOnly){this.status('disconnected',error.message);this.reconnect();}}).finally(()=>{clearTimeout(deadline);if(this.connectionController===controller)this.connectionController=null;this.connecting=null;});
    return this.connecting;
  }
  reconnect(){
    if(this.destroyed||this.localOnly)return;
    clearTimeout(this.timer);const delay=this.retry;this.retry=Math.min(30000,this.retry*2);this.timer=setTimeout(()=>this.connect(),delay);
  }
  handle(value){
    requireThat(value?.policy_sha256===this.policy,'Guest network policy changed');
    if(value.type==='codi-guest-network-challenge/1'){
      requireThat(fields(value,['type','nonce','connection_id','policy_sha256','expires_at'])&&nonce(value.nonce)&&nonce(value.connection_id)&&Number.isSafeInteger(value.expires_at)&&value.expires_at>nowSeconds()&&value.expires_at<=nowSeconds()+31,'Invalid guest challenge');
      const epoch=this.epoch;this.authorize(value,epoch).catch(error=>this.failAuthorization(error,epoch));
    }else if(value.type==='codi-guest-network-ready/1'){
      const pending=this.pendingGrant;
      requireThat(fields(value,['type','kind','expires_at','connection_id','policy_sha256'])&&value.kind==='registered'&&pending&&pending.epoch===this.epoch&&pending.session===this.getSession()&&value.connection_id===pending.connection&&Number.isSafeInteger(value.expires_at)&&value.expires_at>nowSeconds()&&value.expires_at<=pending.expires,'Unbound guest worker acknowledgement');
      this.pendingGrant=null;this.authRequested=false;this.status('registered');
    }else if(value.type==='codi-guest-network-state/1'){
      requireThat(fields(value,['type','kind','policy_sha256'])&&['anonymous','registered'].includes(value.kind),'Invalid guest network state');
      if(value.kind==='anonymous'){
        this.status('anonymous');this.pendingGrant=null;
        if(this.resetAck)this.resetAck=false;
        else{this.authRequested=false;this.nextAuth=Date.now()+15000;}
      }else if(this.mode!=='registered')this.reset();
    }else throw Error('Unknown guest network control');
  }
  failAuthorization(error,epoch){
    if(this.destroyed||epoch!==this.epoch)return;
    this.reset();this.nextAuth=Date.now()+15000;this.status('anonymous','Registered network access unavailable: '+error.message);
  }
  async authorize(challenge,epoch){
    const session=this.getSession();requireThat(session?.public.kind==='registered','Registered session required');
    const sid=session.public.sid,key=session.public.key;
    const valid=()=>!this.destroyed&&this.controlled&&epoch===this.epoch&&this.getSession()===session&&session.public.sid===sid&&sameKey(session.public.key,key)&&this.socket?.readyState===WebSocket.OPEN;
    this.controller?.abort();const controller=new AbortController();this.controller=controller;
    const deadline=setTimeout(()=>controller.abort(),10000);
    const post=async(path,value,token=null)=>{
      requireThat(valid(),'Guest session changed');
      const response=await fetch(path,{method:'POST',mode:'same-origin',credentials:'same-origin',redirect:'error',cache:'no-store',signal:controller.signal,headers:{'Content-Type':'application/json',...(token?{Authorization:'Codi '+token}:{})},body:JSON.stringify(value)});
      const reader=response.body.getReader(),chunks=[];let length=0;
      try{while(true){const {done,value}=await reader.read();if(done)break;length+=value.length;requireThat(length<=16384,'Guest authorization response too large');chunks.push(value);}}
      catch(error){await reader.cancel().catch(()=>{});throw error;}
      const bytes=new Uint8Array(length);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
      const result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));requireThat(valid(),'Guest session changed');
      if(!response.ok)throw Error(result.error||'Guest authorization failed');return result;
    };
    try{
      await verifyIdentity(session.public,this.config.identity);requireThat(valid(),'Guest session changed');
      const authorize=this.api+'/authorize',ch=await post(this.api+'/challenge',{key,path:authorize});
      requireThat(nonce(ch.nonce)&&Number.isSafeInteger(ch.expires_at)&&ch.expires_at>nowSeconds(),'Invalid issuer challenge');
      const request=JSON.stringify({nonce:challenge.nonce,connection_id:challenge.connection_id,policy_sha256:this.policy}),now=nowSeconds();
      const proof=await signJws({v:1,nonce:ch.nonce,iss:sid,aud:this.config.identity.issuer,method:'POST',path:authorize,iat:now,exp:now+60,request_sha256:await hash(request)},session.privateKey,REQUEST_TYPE);
      const result=await post(authorize,{request,proof},session.token),header=inspectJws(result.grant,GRANT_TYPE,8192).header;
      const authority=this.config.identity.authorityKeys.find(k=>k.kid===header.kid);requireThat(authority,'Untrusted guest network authority');
      const grant=await verifyJws(result.grant,authority.jwk,GRANT_TYPE,8192);validateTimes(grant,30);
      requireThat(fields(grant,['v','iss','aud','sub','sid','kind','cnf','iat','exp','jti','nonce','connection_id','policy_sha256','session_deadline'])&&grant.v===1&&grant.iss===this.config.identity.issuer&&grant.aud===location.origin+this.path&&grant.kind==='registered'&&grant.sub===session.public.sub&&grant.sid===sid&&sameKey(grant.cnf?.jwk,key)&&grant.nonce===challenge.nonce&&grant.connection_id===challenge.connection_id&&grant.policy_sha256===this.policy&&Number.isSafeInteger(grant.session_deadline)&&grant.session_deadline>=grant.exp&&nonce(grant.jti),'Guest grant context changed');
      const use=await signJws({v:1,iss:sid,aud:grant.aud,nonce:challenge.nonce,grant_sha256:await hash(result.grant),connection_id:challenge.connection_id,policy_sha256:this.policy,method:'CONNECT',path:this.path,iat:grant.iat,exp:grant.exp},session.privateKey,USE_TYPE);
      requireThat(valid(),'Guest session changed');this.authRequested=true;this.pendingGrant={epoch,session,connection:challenge.connection_id,expires:grant.exp};
      this.control({type:'codi-guest-network-auth/1',grant:result.grant,proof:use});
    }finally{clearTimeout(deadline);if(this.controller===controller)this.controller=null;}
  }
  destroy(){
    this.destroyed=true;++this.epoch;clearTimeout(this.timer);this.controller?.abort();this.connectionController?.abort();this.queue=[];this.socket?.close();this.socket=null;
  }
}
