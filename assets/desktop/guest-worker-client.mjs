const NINE_P_MAX = 1024 * 1024;

function ninePError(request) {
 const response=new Uint8Array(11);
 const view=new DataView(response.buffer);
 view.setUint32(0,response.length,true);
 response[4]=7; // RLERROR
 response.set(request.subarray(5,7),5);
 view.setUint32(7,5,true); // EIO
 return response;
}

/** Browser-side bounded guest Worker transport used by the desktop. */
export class GuestWorkerClient{
 #worker;#pending=new Map();#next=0;#listeners=new Map();#closed=false;#terminationFailed=false;#terminationError;#fatal;#timeout;#incomingFrames=0;
 #accountPort=null;
 constructor(url,{onFatal=()=>{},timeoutMs=30000}={}){
  if(!Number.isInteger(timeoutMs)||timeoutMs<1000||timeoutMs>120000)throw Error('Invalid guest request timeout.');this.#timeout=timeoutMs;this.#fatal=onFatal;this.#worker=new Worker(url);
  this.bus={register:(name,fn,owner)=>{if(name!=='net0-send'||typeof fn!=='function')throw Error('Unsupported guest bus listener.');this.#listeners.set(name,fn.bind(owner));},send:(name,frame)=>{if(name!=='net0-receive'||!(frame instanceof Uint8Array)||frame.length<14||frame.length>1518||this.#closed||this.#incomingFrames>=64)return;this.#incomingFrames++;try{this.#worker.postMessage({type:'frame',frame});}catch(error){this.#incomingFrames--;throw error;}}};
  this.#worker.onmessage=({data})=>this.#receive(data);this.#worker.onerror=event=>this.#fail(Error(event.message||'Guest worker failed.'));this.#worker.onmessageerror=()=>this.#fail(Error('Guest worker message failed.'));
 }
 #receive(data){if(this.#closed||!data||typeof data!=='object')return;if(data.type==='fatal'){this.#fail(Error(String(data.message||'Guest worker failed.')));return;}if(data.type==='reply'){const p=this.#pending.get(data.id);if(!p)return;this.#pending.delete(data.id);clearTimeout(p.timer);data.ok?p.resolve(data.value):p.reject(Error(String(data.error||'Guest request failed.')));return;}if(data.type==='frame-received'){if(this.#incomingFrames>0)this.#incomingFrames--;return;}if(data.type==='frame'){const frame=data.frame;try{if(frame instanceof Uint8Array&&frame.length>=14&&frame.length<=1518)this.#listeners.get('net0-send')?.(frame);}finally{if(!this.#closed)this.#worker.postMessage({type:'frame-ack'});}return;}if(data.type==='ready')this.#listeners.get('emulator-ready')?.();else if(data.type==='serial'&&typeof data.text==='string')for(const char of data.text)this.#listeners.get('serial0-output-byte')?.(char.charCodeAt(0));else if(data.type==='download-error')this.#listeners.get('download-error')?.(data.event);}
 #fail(error){if(this.#closed)return;try{this.close();}catch(terminationError){this.#fatal(new AggregateError([error,terminationError],`${error.message} Worker termination could not be confirmed.`));return;}this.#fatal(error);}
 start(options,{handleAccountRequest}={}){
  if(this.#closed)throw Error('Guest worker is closed.');
  if(handleAccountRequest===undefined){this.#worker.postMessage({type:'start',options});return;}
  if(typeof handleAccountRequest!=='function'||this.#accountPort)throw Error('Invalid account filesystem handler.');
  const {port1,port2}=new MessageChannel();
  this.#accountPort=port1;
  port1.onmessage=async ({data:request})=>{
   if(this.#closed)return;
   if(!(request instanceof Uint8Array)||request.length<7||request.length>NINE_P_MAX){
    this.#fail(Error('Invalid account filesystem packet.'));return;
   }
   let response;
   try{
    const result=await handleAccountRequest(request);
    if(!(result instanceof Uint8Array)||result.length<7||result.length>NINE_P_MAX||
       result[5]!==request[5]||result[6]!==request[6])throw Error('Invalid account filesystem response.');
    response=result.slice();
   }catch{response=ninePError(request);}
   if(!this.#closed)port1.postMessage(response,[response.buffer]);
  };
  port1.onmessageerror=()=>this.#fail(Error('Account filesystem message could not be read.'));
  try{this.#worker.postMessage({type:'start',options,accountPort:port2},[port2]);}
  catch(error){port1.close();port2.close();this.#accountPort=null;throw error;}
 }
 add_listener(name,fn){if(!['emulator-ready','serial0-output-byte','download-error'].includes(name)||typeof fn!=='function')throw Error('Unsupported guest event.');this.#listeners.set(name,fn);}
 serial0_send(text){if(this.#closed)throw Error('Guest worker is closed.');if(typeof text!=='string'||text.length>65536)throw Error('Invalid terminal input.');this.#worker.postMessage({type:'serial',text});}
 request(method,...args){if(this.#closed)return Promise.reject(Error('Guest worker is closed.'));if(this.#pending.size>=64)return Promise.reject(Error('Guest request queue is full.'));const id=++this.#next;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{this.#pending.delete(id);reject(Error('Guest request timed out; it may have completed.'));},this.#timeout);this.#pending.set(id,{resolve,reject,timer});try{this.#worker.postMessage({type:'rpc',id,method,args});}catch(error){clearTimeout(timer);this.#pending.delete(id);reject(error);}});}
 create_file(path,bytes){return this.request('write',path,bytes);}
 read_file(path){return this.request('read',path);}
 close(){if(this.#closed){if(this.#terminationFailed)throw this.#terminationError;return;}this.#closed=true;this.#accountPort?.close();try{this.#worker.terminate();}catch(error){this.#terminationFailed=true;this.#terminationError=error;throw error;}finally{for(const p of this.#pending.values()){clearTimeout(p.timer);p.reject(Error('Guest worker closed; an in-flight operation may have completed.'));}this.#pending.clear();this.#listeners.clear();}}
 async destroy(){this.close();}
 async stop(){this.close();}
}
