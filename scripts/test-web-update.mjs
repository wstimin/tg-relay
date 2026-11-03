import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {esc} from '../web/icons.mjs';

// Execute the shipped controller with deterministic network/timers, without copying its logic.
const app=await readFile(new URL('../web/app.mjs',import.meta.url),'utf8');
const controller=app.slice(app.indexOf('let authEpoch='),app.indexOf("let state=null,page="));
function fixture(responses){
  let now=1000,reloads=0,nextID=0;
  const timers=new Map(),calls=[],elements=new Map(['#update-notice','#update-panel','#update-progress-body','#settings-form'].map(key=>[key,{dataset:{}}]));
  const context=vm.createContext({
    $:key=>elements.get(key),document:{querySelectorAll:()=>[]},state:{version:'v0.4.1'},esc,
    bytes:n=>`${n} B`,time:v=>v,button:(name,action)=>`<button data-action="${action}">${name}</button>`,icon:()=>'',info:t=>t,
    location:{reload:()=>reloads++},AbortSignal,
    Date:class extends Date{static now(){return now;}},
    setTimeout:(fn,delay)=>{const id=++nextID;timers.set(id,{fn,delay});return id;},clearTimeout:id=>timers.delete(id),
    fetch:async url=>{calls.push(url);assert.ok(responses.length,`unexpected fetch ${url}`);const next=responses.shift();if(next instanceof Error)throw next;if(typeof next==='function')return next();return new Response(JSON.stringify(next.body??next),{status:next.status??200});},
  });
  vm.runInContext(controller,context);
  vm.runInContext(`updateState={current:'v0.4.1',latest:'v0.4.2',progress:{phase:'queued',target:'v0.4.2'}};watchUpdate();`,context);
  const flush=()=>new Promise(resolve=>setImmediate(resolve));
  return {context,elements,calls,timers,flush,get reloads(){return reloads;},advance:ms=>now+=ms,
    async tick(){await flush();const [id,timer]=timers.entries().next().value??[];assert.ok(timer,'missing next timer');timers.delete(id);await timer.fn();await flush();},
    value:expression=>vm.runInContext(expression,context)};
}
const status=(phase,extras={})=>({current:'v0.4.1',latest:'v0.4.2',progress:{phase,target:'v0.4.2',...extras}});
{
  let resolve;
  const f=fixture([()=>new Promise(done=>resolve=done)]);await f.flush();f.value('watchUpdate()');assert.equal(f.calls.length,1);assert.equal(f.timers.size,0);
  resolve(new Response(JSON.stringify(status('queued'))));await f.flush();assert.equal(f.timers.size,1);
}
{
  const f=fixture([status('downloading',{downloaded:25,total:100}),new Error('restart disconnected'),{status:401},
    {version:'v0.4.2',ready:false,updatePhase:'validating',updateTarget:'v0.4.2'},
    {status:401},{version:'v0.4.2',ready:true,updatePhase:'complete',updateTarget:'v0.4.2'}]);
  await f.flush();assert.match(f.elements.get('#update-progress-body').innerHTML,/aria-valuenow="25"/);
  await f.tick();assert.match(f.elements.get('#update-progress-body').innerHTML,/正在等待服务恢复/);
  await f.tick();assert.equal(f.reloads,0);assert.equal(f.value('updateStarted>0'),true);
  await f.tick();assert.equal(f.reloads,0);assert.match(f.elements.get('#update-progress-body').innerHTML,/aria-valuenow="100"/);
  await f.tick();assert.equal(f.reloads,1);assert.equal(f.timers.size,0);assert.equal(f.calls.filter(x=>x==='/api/auth').length,2);
}
for(const auth of [
  {version:'v0.4.1',ready:true,updatePhase:'complete',updateTarget:'v0.4.1'},
  {version:'v0.4.2',ready:true,updatePhase:'complete',updateTarget:'v0.9.0'},
  {version:'v0.4.2',ready:false,updatePhase:'complete',updateTarget:'v0.4.2'},
]){
  const f=fixture([{status:401},auth]);await f.flush();assert.equal(f.reloads,0);assert.equal(f.value('updateStarted>0'),true);
}
{
  const f=fixture([status('failed',{message:'SHA256 mismatch'})]);await f.flush();assert.equal(f.reloads,0);assert.equal(f.timers.size,0);assert.match(f.elements.get('#update-progress-body').innerHTML,/SHA256 mismatch/);
}
{
  const f=fixture([status('downloading',{downloaded:25})]);await f.flush();assert.doesNotMatch(f.elements.get('#update-progress-body').innerHTML,/aria-valuenow=/);
  f.advance(600001);await f.tick();assert.equal(f.reloads,0);assert.equal(f.timers.size,0);assert.match(f.elements.get('#update-progress-body').innerHTML,/重新获取进度/);
}
{
  const f=fixture([status('complete'),{version:'v0.4.2',ready:true,updatePhase:'complete',updateTarget:'v0.4.2'}]);await f.flush();await f.tick();assert.equal(f.reloads,1);
}
console.log('Update progress, restart recovery, failure handling and verified automatic reload passed.');
