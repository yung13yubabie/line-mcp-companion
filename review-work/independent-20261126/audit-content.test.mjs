// Independent defensive test. Synthetic in-memory SQLite only; no sockets or credentials.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {openDatabase} from '../../src/storage/db.ts';
import {Audit} from '../../src/ai/audit.ts';
test('generic activity audit must not persist plaintext message and prompt snapshots', () => {
 const store = openDatabase(':memory:');
 try {
  const audit = new Audit(store);
  audit.log('ui','suggestion_generated',{chatId:'synthetic-chat',detail:{flags:[],text:'SYNTHETIC_PRIVATE_MESSAGE_20261126',style:'plain'}});
  audit.log('ui','image_generated',{chatId:'synthetic-chat',detail:{prompt:'SYNTHETIC_PRIVATE_PROMPT_20261126',bytes:128}});
  const rows=store.db.prepare('SELECT detail FROM audit_log ORDER BY id').all();
  assert.equal(JSON.stringify(rows).includes('SYNTHETIC_PRIVATE_MESSAGE_20261126'),false,'message snapshot must be absent or sealed');
  assert.equal(JSON.stringify(rows).includes('SYNTHETIC_PRIVATE_PROMPT_20261126'),false,'prompt snapshot must be absent or sealed');
  const visible=audit.recent();
  assert.equal(visible.length,2,'audit still records the two operations');
  assert.equal(visible[0].action,'image_generated','metadata remains useful');
 } finally {store.close();}
});

test('legacy audit details are scrubbed and bounded operational metadata remains available', () => {
 const store=openDatabase(':memory:');
 try {
  store.db.exec('CREATE TABLE IF NOT EXISTS security_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, chat_id TEXT, ok INTEGER NOT NULL DEFAULT 0, detail TEXT)');
  store.db.prepare('INSERT INTO audit_log(ts,actor,action,ok,detail) VALUES (?, ?, ?, ?, ?)').run(1,'ui','suggestion_generated',1,JSON.stringify({id:17,bytes:128,text:'LEGACY_PRIVATE_TEXT_20261126',error:'LEGACY_ERROR_CONTENT_20261126',client:'LEGACY_CLIENT_CONTENT_20261126'}));
  store.db.prepare('INSERT INTO security_log(ts,actor,action,ok,detail) VALUES (?, ?, ?, ?, ?)').run(1,'mcp','mcp_auth_failures',0,JSON.stringify({count:2,token:'LEGACY_SYNTHETIC_TOKEN_20261126',reason:'LEGACY_REASON_TEXT_20261126'}));
  const audit=new Audit(store);
  const raw=JSON.stringify({activity:store.db.prepare('SELECT detail FROM audit_log').all(),security:store.db.prepare('SELECT detail FROM security_log').all()});
  assert.equal(raw.includes('LEGACY_'),false,'legacy freeform text must be scrubbed on initialization');
  audit.log('ui','operation_completed',{detail:{id:19,bytes:128,error:'NEW_ERROR_CONTENT_20261126',text:'NEW_PRIVATE_TEXT_20261126',nested:{prompt:'NESTED_PRIVATE_PROMPT_20261126'}}});
  const detail=JSON.parse(store.db.prepare("SELECT detail FROM audit_log WHERE action='operation_completed'").get().detail);
  assert.equal(detail.id,19);
  assert.equal(detail.bytes,128);
  assert.equal(JSON.stringify(detail).includes('PRIVATE'),false);
  assert.equal(JSON.stringify(detail).includes('ERROR_CONTENT'),false);
  // A second initialization may not resurrect legacy details or remove the audit events.
  new Audit(store);
  assert.equal(audit.recent().length,2);
 } finally {store.close();}
});

test('file-backed legacy minimization checkpoints current SQLite and WAL bytes', async()=>{
 const {mkdtempSync,readFileSync,existsSync,rmSync}=await import('node:fs');
 const {tmpdir}=await import('node:os');
 const {join}=await import('node:path');
 const dir=mkdtempSync(join(tmpdir(),'lma-independent-audit-'));
 const path=join(dir,'line.db');
 let store;
 try {
  store=openDatabase(path);
  const marker='SYNTHETIC_LEGACY_DISK_MARKER_20261126';
  store.db.prepare('INSERT INTO audit_log(ts,actor,action,ok,detail) VALUES (1,?,?,1,?)').run('ui','fixture',JSON.stringify({text:marker,id:8}));
  assert.ok([path,path+'-wal'].some(p=>existsSync(p)&&readFileSync(p).includes(Buffer.from(marker))),'fixture actually wrote plaintext into the current SQLite/WAL files');
  new Audit(store);
  for(const p of [path,path+'-wal']) if(existsSync(p)) assert.equal(readFileSync(p).includes(Buffer.from(marker)),false,'current database/WAL must not retain the known legacy marker');
  assert.equal(store.db.prepare("SELECT value FROM settings WHERE key='audit_metadata_v1'").get().value,'1');
  assert.equal(JSON.parse(store.db.prepare('SELECT detail FROM audit_log').get().detail).id,8);
 } finally {store?.close();rmSync(dir,{recursive:true,force:true});}
});
