// Actual submit handler, inert DOM, synthetic transport only. No browser/network.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '../templates/ramp_boss.html'), 'utf8');
const begin = html.indexOf("    form.addEventListener('submit', async e => {");
const after = html.indexOf('    function rbSerializeMainForm()', begin);
const end = html.lastIndexOf('    });', after) + '    });'.length;
const locks = html.slice(html.indexOf('    function lockButtons(btn){'), html.indexOf('    //', html.indexOf('    function unlockButtons(){')));
assert(begin >= 0 && after > begin && end > begin);

function setup(outcomes, buttonValue = 'send') {
  let callback, resets = 0, commits = 0, rotations = 0, clock = 1201, builds = 0;
  const posts = [], toasts = [];
  const primary = {value:'send',dataset:{},textContent:'Log Arrival',disabled:false,getAttribute:()=>'/ramp_boss'};
  const queue = {value:'queue',dataset:{},textContent:'Queue',disabled:false,getAttribute:()=>'/queue_flight'};
  const button = buttonValue === 'queue' ? queue : primary;
  const values = {arrival_request_id:'event-original',manifest_id:'cargo-original',direction:'inbound',
    tail_number:'N456',pilot_name:'Pilot',dep_time:'1200',eta:'1200',cargo_weight:'10',remarks:'Rice 5 lb x 2'};
  function field(key) {return {get value(){return values[key];},set value(v){values[key]=v;},classList:{add(){},remove(){}}};}
  const form = {action:'/ramp_boss',addEventListener:(event,fn)=>{callback=fn;},querySelector:()=>field('eta'),
    reset(){resets++;Object.assign(values,{arrival_request_id:'event-original',manifest_id:'',cargo_weight:'',remarks:''});}};
  class FormData {constructor(){builds++;this.saved=Object.entries(values).map(([k,v])=>[k,v]);}entries(){return this.saved[Symbol.iterator]();}}
  const response = {id:7,direction:'inbound',tail_number:'N456',eta:'1200',cargo_weight:'10',action:'new'};
  const context = {form,rbSubmitting:false,sendBtn:primary,queueBtn:queue,
    document:{querySelector:()=>field('direction'),getElementById:()=>primary},
    validateRampBoss:()=>true,originField:{value:'KAAA'},destField:{value:'KBBB'},depField:field('dep_time'),
    travelHInp:{disabled:false},travelMInp:{disabled:false},
    nowHHMM:()=>String(clock++),commitManifest:async()=>{commits++;},xhrHeaders:()=>({'X-Requested-With':'XMLHttpRequest'}),
    FormData,showToast:(...args)=>toasts.push(args),console,window:{},setTimeout:()=>{},
    isEditDraft:false,dirRadios:[{checked:true,value:'inbound'}],applyDirUI:()=>{},
    arrivalRequestId:field('arrival_request_id'),newArrivalRequestId:()=>`event-new-${++rotations}`,
    manifestId:field('manifest_id'),feedbackBox:{innerHTML:''},cwHistory:{innerHTML:''},cwTotalEl:{textContent:''},
    cwMinus:{disabled:false},advLines:{innerHTML:''},totalCargo:10,enablePrintLabelsButton:()=>{},showLabelsToast:()=>{},
    fetch:async(url,opts)=>{
      if (opts.method !== 'POST') return {ok:true,json:async()=>({exists:true})};
      posts.push({url,body:[...opts.body.entries()].map(pair=>[...pair])});
      const outcome=outcomes.shift() || 'success';
      if(outcome==='loss') throw new TypeError('Synthetic lost response');
      return {ok:outcome!=='http',headers:{get:()=>outcome==='nonjson'?'text/html':'application/json'},
        json:async()=>{if(outcome==='json') throw new SyntaxError('Synthetic interrupted JSON');
          return outcome==='null'?null:outcome==='redirect'?{redirect:'/queue'}:response;}};
    }};
  vm.createContext(context);vm.runInContext(locks+'\n'+html.slice(begin,end),context);
  return {context,values,posts,toasts,primary,queue,form,
    submit:()=>callback({preventDefault(){},submitter:button}),
    state:()=>({resets,commits,rotations,builds}),
    pending:()=>vm.runInContext('rbRetryRequest',context)};
}
function unlocked(h){
  assert.equal(h.context.rbSubmitting,false);assert.equal(h.primary.disabled,false);assert.equal(h.queue.disabled,false);
  assert.equal(h.context.travelHInp.disabled,false);assert.equal(h.context.travelMInp.disabled,false);
}
for (const failure of ['loss','json','http','nonjson','null']) {
  test(`${failure}: recover, preserve exact payload and identity, then accept retry`,async()=>{
    const h=setup([failure,'success']);
    await assert.doesNotReject(h.submit());unlocked(h);
    assert.equal(h.posts.length,1);assert.equal(h.values.arrival_request_id,'event-original');
    assert.deepEqual(h.state(),{resets:0,commits:1,rotations:0,builds:1});
    assert.match(h.toasts.at(-1)[0],/Retry.*original details and request ID/);
    const original=h.posts[0];
    // Timer drift, edits, invalid visible time, changed target and ID cannot alter retry.
    Object.assign(h.values,{arrival_request_id:'edited-id',manifest_id:'edited-manifest',dep_time:'bad',remarks:'edited',direction:'outbound'});
    h.context.destField.value='';h.form.action='/different';h.primary.getAttribute=()=>'/different';
    h.context.validateRampBoss=()=>{throw new Error('Retry must not revalidate mutable fields');};
    h.context.commitManifest=async()=>{throw new Error('Retry must not recommit a closed manifest');};
    await assert.doesNotReject(h.submit());unlocked(h);
    assert.deepEqual(h.posts,[original,original]);
    assert.deepEqual(h.state(),{resets:1,commits:1,rotations:1,builds:1});
    assert.equal(h.values.arrival_request_id,'event-new-1');assert.equal(h.pending(),null);
  });
}
test('multiple lost responses keep the same snapshot for every attempt',async()=>{
  const h=setup(['loss','json','success']);
  for(let i=0;i<3;i++){await h.submit();unlocked(h);}
  assert.equal(h.posts.length,3);assert.deepEqual(h.posts[0],h.posts[1]);assert.deepEqual(h.posts[1],h.posts[2]);
  assert.deepEqual(h.state(),{resets:1,commits:1,rotations:1,builds:1});
});
test('confirmed arrival resets once and next deliberate event uses a fresh ID',async()=>{
  const h=setup(['success','success']);await h.submit();unlocked(h);
  const first=Object.fromEntries(h.posts[0].body).arrival_request_id;
  await h.submit();unlocked(h);
  const second=Object.fromEntries(h.posts[1].body).arrival_request_id;
  assert.notEqual(first,second);assert.deepEqual(h.state(),{resets:2,commits:2,rotations:2,builds:2});
});
test('queue retry retains queue target and successful reset behavior',async()=>{
  const h=setup(['loss','success'],'queue');await h.submit();unlocked(h);
  h.queue.value='send';h.queue.getAttribute=()=>'/ramp_boss';await h.submit();unlocked(h);
  assert.equal(h.posts[0].url,'/queue_flight');assert.deepEqual(h.posts[0],h.posts[1]);
  assert(h.toasts.some(t=>t[0]==='Flight added to queue'));
  assert.equal(h.state().resets,1);assert.equal(h.pending(),null);
});
test('confirmed redirect remains honored without resetting the form',async()=>{
  const h=setup(['redirect']);await h.submit();unlocked(h);
  assert.equal(h.context.window.location,'/queue');assert.equal(h.context.window.__RB_INTENTIONAL_NAV,true);
  assert.equal(h.pending(),null);assert.equal(h.state().resets,0);
});
test('manifest preflight failure also restores controls without creating a POST snapshot',async()=>{
  const h=setup([]);h.context.commitManifest=async()=>{throw new Error('Synthetic preflight failure');};
  await h.submit();unlocked(h);assert.equal(h.posts.length,0);assert.equal(h.pending(),null);
  assert.equal(h.values.arrival_request_id,'event-original');assert.equal(h.state().resets,0);
});
