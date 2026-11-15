// Exercises the actual client with a test-double Worker; no VM is started.
import test from 'node:test';
import assert from 'node:assert/strict';
import {GuestWorkerClient} from '../../assets/desktop/guest-worker-client.mjs';

for (const event of ['error','messageerror','fatal']) for (const terminateFails of [false,true]) test(`${event} reports worker failure${terminateFails?' and termination failure':''}`,async()=>{
 const previous=globalThis.Worker;let worker,terminations=0;const fatals=[];
 globalThis.Worker=class{constructor(){worker=this}postMessage(){}terminate(){terminations++;if(terminateFails)throw Error('injected terminate failure')}};
 try{
  const client=new GuestWorkerClient('http://127.0.0.1/worker',{onFatal:error=>fatals.push(error)});
  const pending=assert.rejects(client.read_file('/test'),/in-flight operation may have completed/);
  if(event==='error')worker.onerror({message:'injected worker error'});else if(event==='messageerror')worker.onmessageerror();else worker.onmessage({data:{type:'fatal',message:'injected worker error'}});await pending;
  assert.equal(fatals.length,1);assert.match(fatals[0].message,event==='messageerror'?/Guest worker message failed/:/injected worker error/);
  if(terminateFails){assert.ok(fatals[0] instanceof AggregateError);assert.match(fatals[0].message,/termination could not be confirmed/);assert.match(fatals[0].errors[1].message,/injected terminate failure/);await assert.rejects(client.stop(),/injected terminate failure/)}
  else{assert.doesNotMatch(fatals[0].message,/termination could not be confirmed/);await client.stop()}
  worker.onmessage({data:{type:'fatal',message:'another error'}});assert.equal(fatals.length,1);assert.equal(terminations,1);
  await assert.rejects(client.read_file('/test'),/closed/);
 }finally{globalThis.Worker=previous}
});
