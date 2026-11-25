import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { openDatabase } from '../src/storage/db.ts';
import { SecretBox } from '../src/storage/secret-box.ts';
import { DigestStore } from '../src/storage/digests.ts';
import { Whitelist } from '../src/whitelist.ts';
import { AiPolicy } from '../src/ai/policy.ts';
import { Audit } from '../src/ai/audit.ts';
import { Outbox } from '../src/ai/outbox.ts';
import { AiService } from '../src/ai/service.ts';
import { OpenAICompatProvider, AiError } from '../src/ai/provider.ts';
import { callTool } from '../src/mcp/tools.ts';
import { MediaCache } from '../src/media/cache.ts';
import { DigestPoster } from '../src/ai/digest-post.ts';
import { mcpSendFlags } from '../src/mcp/tools.ts';
import { sanitizeReply } from '../src/ai/prompt.ts';
import { ScamDetector } from '../src/scam/detector.ts';

// Every fixture uses synthetic data, an in-memory database, fake providers/senders.
// Global fetch defaults to a refusal so accidental real network calls cannot occur.
globalThis.fetch = async () => { throw new Error('audit_network_forbidden'); };
const CHAT = 'c_synthetic_a';
const T0 = Date.parse('2026-11-25T10:00:00+08:00');


function setup(reply = '好喔') {
  const dir = mkdtempSync(join(tmpdir(), 'lma-red-audit-'));
  const store = openDatabase(':memory:');
  store.upsertChat({id:CHAT,type:'GROUP',name:'Synthetic Group'});
  store.upsertParticipant('u_synthetic_sender','陳測試');
  store.insertMessage({chatId:CHAT,id:'m1',senderMid:'u_synthetic_sender',fromSelf:false,sentAt:T0-1000,contentType:'NONE',text:'陳測試的電話是0912345678，今天見面。'});
  const wl = new Whitelist(store); wl.set(CHAT,true);
  const clock = {t:T0,now(){return this.t},minuteOfDay(){return 600},startOfDay(t:number){return Math.floor(t/86400000)*86400000}};
  const policy = new AiPolicy(store,clock);
  const audit = new Audit(store);
  const sent:any[]=[];
  const sender = {async sendText(chatId:string,text:string){sent.push({chatId,text})},async sendImage(){sent.push({kind:'image'})},async sendSticker(){sent.push({kind:'sticker'})}};
  const outbox = new Outbox(store,policy,audit,sender);
  const calls:any[]=[];
  const provider = {kind:'custom' as const,reply, async chat(messages:any[]){calls.push(structuredClone(messages)); return this.reply}, async generateImage(){return {bytes:new Uint8Array([0x89,0x50]),mime:'image/png'}}, async detect(){return {text:true,vision:false,image_gen:true,voice:false,models:[],checked_at:0,heuristic:true}}};
  const ai = new AiService(store,policy,outbox,audit,{home:dir,getKey:()=> 'synthetic-test-key-not-real',providerFactory:()=>provider});
  const ds = new DigestStore(store,new SecretBox(randomBytes(32)),wl); ai.digests=ds;
  const ctx:any={store,whitelist:wl,sync:null,media:null,ai,digests:ds};
  function enable(){policy.setAiEnabled(true);policy.set(CHAT,{ai_allowed:true,mode:'auto',allow_image:true,style_lieflat:false,delay_sec:0,max_per_hour:60,max_per_day:100,min_interval_sec:10});policy.setTrust(CHAT,'ai','auto');}
  function close(){ai.stop();store.close();rmSync(dir,{recursive:true,force:true});}
  return {dir,store,wl,clock,policy,audit,outbox,sent,sender,provider,calls,ai,ds,ctx,enable,close};
}

test('privacy: social drafting redacts personal data before provider call',async()=>{
  const f=setup();try{
    f.enable();
    f.ai.setConfig({provider:'custom',base_url:'https://model.synthetic.example/v1',model:'fake',deidentify:true});
    assert.equal(f.ai.shouldDeidentify(),true);
    await f.ai.draftSocialPost({chatId:CHAT,platform:'threads',mode:'A'},'ui');
    const body=JSON.stringify(f.calls[0]);
    assert.ok(!body.includes('陳測試') && !body.includes('0912345678'));
  }finally{f.close()}
});

test('privacy: cloud fallback after local failure receives redacted history',async()=>{
  const f=setup();const oldFetch=globalThis.fetch;try{
    f.enable();
    let fallbackBody:any;
    globalThis.fetch=async (url:any,init:any)=>{
      assert.equal(String(url),'https://fallback.synthetic.example/v1/chat/completions');
      fallbackBody=JSON.parse(init.body);
      return new Response(JSON.stringify({choices:[{message:{content:'好喔'}}]}),{status:200,headers:{'content-type':'application/json'}});
    };
    f.provider.chat=async ()=>{throw new AiError('network','synthetic primary unavailable')};
    f.ai.setConfig({provider:'custom',base_url:'http://127.0.0.1:11434/v1',model:'fake-local',deidentify:true,fallback:[{base_url:'https://fallback.synthetic.example/v1',model:'fake-cloud',use_key:true}]});
    assert.equal(f.ai.shouldDeidentify(),true);
    await f.ai.suggest(CHAT,'ui');
    const body=JSON.stringify(fallbackBody.messages);
    assert.ok(!body.includes('陳測試') && !body.includes('0912345678'));
  }finally{globalThis.fetch=oldFetch;f.close()}
});

test('privacy: Lieflat runs before restoring names for local display',async()=>{
  const f=setup('重點：成員A會過來。');try{
    f.enable();f.policy.set(CHAT,{style_lieflat:true});
    f.ai.setConfig({provider:'custom',base_url:'https://model.synthetic.example/v1',model:'fake',deidentify:true});
    const suggestion=await f.ai.suggest(CHAT,'ui');
    assert.ok(suggestion.text.includes('陳測試'));
    assert.equal(f.calls.length,2);
    assert.equal(JSON.stringify(f.calls[0]).includes('陳測試'),false);
    assert.equal(JSON.stringify(f.calls[1]).includes('陳測試'),false);
  }finally{f.close()}
});

test('consent: disabled AI or missing chat consent prevents scheduled digest model calls',async()=>{
  const f=setup(JSON.stringify({title:'測試日報',items:[{headline:'測試摘要',body:'測試內容',sources:['#1']}]}));try{
    f.ai.setDriver('builtin');
    const poster=new DigestPoster(f.store,f.ds,f.outbox,f.ai,()=>T0);
    poster.saveSchedule({target_chat:CHAT,source_chats:[CHAT],time_hhmm:'09:00',enabled:true,generate:true},'ui');
    assert.equal(f.policy.aiEnabled,false);assert.equal(f.policy.get(CHAT).ai_allowed,false);
    await poster.tick();
    assert.equal(f.calls.length,0);
    assert.equal(f.ds.list().length,0);
    f.policy.setAiEnabled(true);
    await assert.rejects(f.ai.generateDigest(CHAT,T0-5000,T0,'ui'),/ai_not_allowed/);
    assert.equal(f.calls.length,0);
    f.policy.set(CHAT,{ai_allowed:true});
    const digest=await f.ai.generateDigest(CHAT,T0-5000,T0,'ui');
    assert.equal(digest.items.length,1);
    assert.equal(f.calls.length,1);
  }finally{f.close()}
});

test('attachments: hidden cached media and metadata are blocked',async()=>{
  const f=setup();try{
    f.store.insertMessage({chatId:CHAT,id:'media1',senderMid:'u_synthetic_sender',fromSelf:false,sentAt:T0,contentType:'FILE',text:null,mediaName:'synthetic-hidden.txt'});
    const path=join(f.dir,'synthetic-hidden.txt');writeFileSync(path,'SYNTHETIC HIDDEN MEDIA');
    f.store.putMedia(CHAT,'media1',path,'text/plain',22);f.store.markHidden(CHAT,'media1','unsent');
    f.ctx.media=new MediaCache(f.dir,f.store,null);
    await assert.rejects(callTool(f.ctx,'download_media',{chat_id:CHAT,message_id:'media1',inline:true}),/message_hidden/);
    await assert.rejects(callTool(f.ctx,'get_attachment',{chat_id:CHAT,message_id:'media1'}),/message_hidden/);
    const rows: any = await callTool(f.ctx, 'get_messages', { chat_id: CHAT });
    const tombstone = rows.messages.find((m: any) => m.message_id === 'media1');
    assert.equal(tombstone.hidden, 'unsent');
    assert.equal(tombstone.text, null);
    assert.equal(tombstone.media, undefined);
  }finally{f.close()}
});

test('dispatch: cancellation during previous send prevents later queued item from being sent',async()=>{
  const f=setup();try{
    f.enable();
    const one=f.outbox.enqueue({chatId:CHAT,kind:'text',text:'first',origin:'ui',forcePending:true},'ui').item;
    const two=f.outbox.enqueue({chatId:CHAT,kind:'text',text:'cancel me',origin:'ui',forcePending:true},'ui').item;
    f.outbox.approve(one.id,null,'ui');f.outbox.approve(two.id,null,'ui');
    let release!:()=>void;let started!:()=>void;
    const hold=new Promise<void>(r=>release=r), began=new Promise<void>(r=>started=r);
    f.sender.sendText=async (chatId,text)=>{f.sent.push({chatId,text});if(text==='first'){started();await hold}};
    const processing=f.outbox.processDue();await began;
    f.outbox.reject(two.id,'ui');assert.equal(f.outbox.get(two.id)!.status,'rejected');
    release();await processing;
    assert.equal(f.sent.some(x=>x.text==='cancel me'),false);assert.equal(f.outbox.get(two.id)!.status,'rejected');
    assert.equal(f.outbox.get(one.id)!.status,'sent');
  }finally{f.close()}
});

test('dispatch: AUTO to REVIEW demotion requires approval for previously automatic item',async()=>{
  const f=setup();try{
    f.enable();f.store.setSetting(`mcp_send_ok:${CHAT}`,'on');
    const it:any=await callTool(f.ctx,'send_message',{chat_id:CHAT,text:'scheduled before demotion'});
    assert.equal(it.status,'approved');assert.equal(f.outbox.get(it.id)!.decided_at,null);
    f.policy.setTrust(CHAT,'ai','review','ui');
    await f.outbox.processDue();
    assert.equal(f.sent.length,0);
    assert.equal(f.outbox.get(it.id)!.status,'pending');
    f.outbox.approve(it.id,null,'ui');
    await f.outbox.processDue();
    assert.equal(f.sent.length,1);
  }finally{f.close()}
});

test('attachments: revocation during download blocks completion response',async()=>{
  const f=setup();try{
    f.store.insertMessage({chatId:CHAT,id:'media2',fromSelf:false,sentAt:T0,contentType:'FILE',text:null});
    let release!:()=>void;let started!:()=>void;
    const hold=new Promise<void>(r=>release=r),began=new Promise<void>(r=>started=r);
    const fake:any={async downloadMedia(){started();await hold;return {bytes:Buffer.from('SYNTHETIC AFTER REVOKE'),name:'test.txt',mime:'text/plain'}}};
    f.ctx.media=new MediaCache(f.dir,f.store,fake);
    const pending=callTool(f.ctx,'download_media',{chat_id:CHAT,message_id:'media2',inline:true});
    await began;f.wl.set(CHAT,false);release();
    await assert.rejects(pending,/not allowed/);
    assert.equal(f.wl.isAllowed(CHAT),false);
  }finally{f.close()}
});

test('contacts: active zip/mov/md domains and IPv6 literals require review',async()=>{
  const f=setup();try{
    f.enable();f.store.setSetting(`mcp_send_ok:${CHAT}`,'on');
    for(const domain of ['payment.zip','payment.mov','payment.md']) {
      assert.ok(mcpSendFlags(domain).includes('url_in_output'));
      const queued:any=await callTool(f.ctx,'send_message',{chat_id:CHAT,text:domain});
      assert.equal(queued.status,'pending');
      assert.ok(sanitizeReply(domain,{trustedTexts:[]}).flags.includes('url_in_output'));
    }
    assert.ok(sanitizeReply('[2606:4700:4700::1111]',{trustedTexts:[]}).flags.includes('url_in_output'));
    assert.deepEqual(mcpSendFlags('看 report.pdf'),[]);
    const clean:any=await callTool(f.ctx,'send_message',{chat_id:CHAT,text:'正常訊息'});
    assert.equal(clean.status,'approved');
    await f.outbox.processDue();
    assert.deepEqual(f.sent.map(x=>x.text),['正常訊息']);
  }finally{f.close()}
});

test('attachments: normal downloads succeed and mid-download hidden state blocks cache',async()=>{
  const f=setup();try{
    f.store.insertMessage({chatId:CHAT,id:'normal',fromSelf:false,sentAt:T0,contentType:'FILE',text:null});
    f.store.insertMessage({chatId:CHAT,id:'willhide',fromSelf:false,sentAt:T0,contentType:'FILE',text:null});
    const fake:any={async downloadMedia({id}:{id:string}){
      if(id==='willhide')f.store.markHidden(CHAT,id,'unsent');
      return {bytes:Buffer.from('synthetic-normal'),name:'test.txt',mime:'text/plain'};
    }};
    f.ctx.media=new MediaCache(f.dir,f.store,fake);
    const normal:any=await callTool(f.ctx,'download_media',{chat_id:CHAT,message_id:'normal',inline:true});
    assert.equal(Buffer.from(normal.base64,'base64').toString(),'synthetic-normal');
    await assert.rejects(callTool(f.ctx,'download_media',{chat_id:CHAT,message_id:'willhide',inline:true}),/message_hidden/);
    assert.equal(f.store.getMedia(CHAT,'willhide'),undefined);
  }finally{f.close()}
});

test('search: hidden content is excluded from short queries, FTS and compatible search', async () => {
  const f = setup();
  try {
    f.store.insertMessage({ chatId: CHAT, id: 'hidden-search', sentAt: T0, text: '秘密 SYNTHETIC_HIDDEN_SEARCH' });
    f.store.insertMessage({ chatId: CHAT, id: 'visible-search', sentAt: T0, text: '秘密 SYNTHETIC_VISIBLE_SEARCH' });
    f.store.markHidden(CHAT, 'hidden-search', 'unsent');
    const short: any = await callTool(f.ctx, 'search_messages', { query: '秘密' });
    assert.deepEqual(short.map((m: any) => m.message_id), ['visible-search']);
    assert.deepEqual(await callTool(f.ctx, 'search_messages', { query: 'SYNTHETIC_HIDDEN_SEARCH' }), []);
    assert.deepEqual(await callTool(f.ctx, 'search', { query: 'SYNTHETIC_HIDDEN_SEARCH' }), { results: [] });
    const normal: any = await callTool(f.ctx, 'search_messages', { query: 'SYNTHETIC_VISIBLE_SEARCH' });
    assert.equal(normal.length, 1);
  } finally { f.close(); }
});

test('privacy: known personal data in voice and persona follows the deidentification setting', async () => {
  const f = setup();
  try {
    f.enable();
    f.ai.setConfig({ provider: 'custom', base_url: 'https://model.synthetic.example/v1', model: 'fake', deidentify: true });
    f.ai.setVoice({ opening: '陳測試的電話是0912345678' });
    f.ai.setPersona('陳測試的電話是0912345678');
    await f.ai.draftSocialPost({ chatId: CHAT, platform: 'threads', mode: 'A' }, 'ui');
    await f.ai.suggest(CHAT, 'ui');
    for (const messages of f.calls) {
      const body = JSON.stringify(messages);
      assert.ok(!body.includes('陳測試') && !body.includes('0912345678'));
    }
    f.calls.length = 0;
    f.ai.setConfig({ deidentify: false });
    await f.ai.draftSocialPost({ chatId: CHAT, platform: 'threads', mode: 'A' }, 'ui');
    assert.ok(JSON.stringify(f.calls[0]).includes('0912345678'), 'explicit opt-out remains effective');
  } finally { f.close(); }
});

test('alerts: a previously visible scam message stops appearing after it is hidden', async () => {
  const f = setup();
  try {
    const scam = new ScamDetector(f.store);
    f.ctx.scam = scam;
    const text = 'SYNTHETIC_ONLY 恭喜中獎！立即加賴 abc123 領取獎金，點 https://line-verify.example/pay 輸入信用卡驗證碼';
    f.store.insertMessage({ chatId: CHAT, id: 'visible-alert', sentAt: T0, text });
    assert.notEqual(scam.scanMessage(CHAT, 'visible-alert'), null);
    const before: any = await callTool(f.ctx, 'scan_scam_alerts', { chat_id: CHAT });
    assert.equal(before.alerts.length, 1);
    assert.equal(before.alerts[0].text, text);
    f.store.markHidden(CHAT, 'visible-alert', 'unsent');
    const after: any = await callTool(f.ctx, 'scan_scam_alerts', { chat_id: CHAT });
    assert.deepEqual(after.alerts, []);
  } finally { f.close(); }
});
