import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';

const app=await readFile(new URL('../web/app.mjs',import.meta.url),'utf8');
const css=await readFile(new URL('../web/ui.css',import.meta.url),'utf8');
// Exercise shipped asynchronous form logic, including edits made before detection completes.
function fixture(){
  const fields=Object.fromEntries(Object.entries({entityID:'',name:'',port:'',listenIP:'0.0.0.0',publicHost:''}).map(([name,value])=>[name,{name,value}]));
  const messages={'#port-source':{textContent:''},'#entry-source':{textContent:''}};
  const form={id:'inbound-form',elements:fields,isConnected:true,querySelector:key=>messages[key]};
  const requests=[];
  let inputHandler;
  for(const input of Object.values(fields))input.form=form;
  const context=vm.createContext({form,document:{documentElement:{dataset:{input:'pointer'}},addEventListener:(_,handler)=>inputHandler=handler},FormData:class{constructor(form){this.form=form;}entries(){return Object.entries(this.form.elements).map(([key,input])=>[key,input.value]);}},api:url=>new Promise((resolve,reject)=>requests.push({url,resolve,reject}))});
  vm.runInContext(app.slice(app.indexOf('const drafts='),app.indexOf('function mountForm('))+app.slice(app.indexOf('function detectedValue('),app.indexOf('function editInbound(')),context);
  vm.runInContext("formStates.set(form,{key:'new',baseline:JSON.stringify(formValues(form)),edits:{}})",context);
  vm.runInContext(app.slice(app.indexOf("document.addEventListener('input'"),app.indexOf("document.addEventListener('change'")),context);
  return {form,messages,requests,run:code=>vm.runInContext(code,context),edit(name,value){fields[name].value=value;inputHandler({target:fields[name]});}};
}
{
  const f=fixture(),port=f.run('detectPort(form,false)'),host=f.run('detectEntry(form,false)');
  f.requests[0].resolve({port:49152,listenIP:'0.0.0.0'});await port;
  f.requests[1].resolve({host:'relay.example.com',source:'fixture'});await host;
  assert.equal(f.form.elements.port.value,'49152');assert.equal(f.run('dirty(form)'),false);
  assert.equal(f.run('drafts.size'),0);
}
{
  const f=fixture(),port=f.run('detectPort(form,false)'),host=f.run('detectEntry(form,false)');f.edit('name','正在输入');
  f.requests[1].resolve({host:'relay.example.com',source:'fixture'});await host;
  f.requests[0].resolve({port:49153,listenIP:'0.0.0.0'});await port;
  assert.equal(f.form.elements.name.value,'正在输入');assert.equal(f.run('dirty(form)'),true);
  assert.equal(f.run('JSON.parse(formStates.get(form).baseline).find(([name])=>name==="name")[1]'),'');
  assert.equal(f.run('drafts.get("new").find(([name])=>name==="port")[1]'),'49153');
}
for(const field of ['port','publicHost']){
  const f=fixture(),pending=f.run(field==='port'?'detectPort(form,false)':'detectEntry(form,false)');
  f.edit(field,'manual');f.edit(field,''); // Returning to the initial value must not permit a stale overwrite.
  f.requests[0].resolve({port:49154,listenIP:'0.0.0.0',host:'relay.example.com',source:'fixture'});await pending;
  assert.equal(f.form.elements[field].value,'');
}
{
  const f=fixture(),first=f.run('detectPort(form,false)'),second=f.run('detectPort(form,true)');
  f.requests[1].resolve({port:49155,listenIP:'0.0.0.0'});await second;
  f.requests[0].resolve({port:49156,listenIP:'0.0.0.0'});await first;
  assert.equal(f.form.elements.port.value,'49155');assert.equal(f.run('dirty(form)'),true);
}
for(const change of [f=>f.form.isConnected=false,f=>f.edit('listenIP','127.0.0.1')]){
  const f=fixture(),pending=f.run('detectPort(form,false)');change(f);
  f.requests[0].resolve({port:49157,listenIP:'0.0.0.0'});await pending;assert.equal(f.form.elements.port.value,'');
}
{
  const f=fixture();f.edit('port','8023');const pending=f.run('detectPort(form,true)');
  f.requests[0].reject(new Error('检测失败'));await pending;assert.equal(f.form.elements.port.value,'8023');assert.equal(f.messages['#port-source'].textContent,'检测失败');
}
{
  const f=fixture(),pending=f.run('detectPort(form,false)');f.requests[0].resolve({port:0,listenIP:'0.0.0.0'});await pending;
  assert.equal(f.form.elements.port.value,'');assert.match(f.messages['#port-source'].textContent,/无效/);
}
{
  const f=fixture();f.form.id='outbound-form';f.form.querySelector=()=>null;
  assert.doesNotThrow(()=>f.edit('port','1080'));assert.equal(f.run('dirty(form)'),true);
}
// Entrance animations must depend on the immutable mount attribute, never live input modality.
assert.match(css,/\.overlay\[data-entry="pointer"\]>.dialog:not\(\[data-reused\]\)/);
assert.doesNotMatch(css,/html\[data-input="keyboard"\][^{}]*(?:\.dialog|\.overlay|\.auth-intro|\.auth-card)/);
assert.match(app,/data-entry="\$\{entryMode\(\)\}" data-backdrop/);
assert.doesNotMatch(app,/function availablePort/);
console.log('Form detection, manual edits, stale responses, drafts and stable entrance rules passed.');
