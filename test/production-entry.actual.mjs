/** Actual production-bundle host entry. Fresh synthetic storage, no LINE login or message reads;
 * never Android/UI/device/upgrade acceptance. Run after the compiler tests restore production output. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { request } from 'node:http';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js';
const key='synthetic-production-entry-mcp-key',control='synthetic-production-entry-control-key';
const digest=data=>createHash('sha256').update(data).digest('hex');
const proof=value=>createHmac('sha256',control).update(value).digest('hex');
function get(url,headers={}) {
 return new Promise((ok,bad)=>{const req=request(url,{method:'GET',headers,timeout:5000},res=>{
  const chunks=[];res.on('data',x=>chunks.push(x));res.on('end',()=>ok({status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks)}));res.on('error',bad);
 });req.on('error',bad);req.on('timeout',()=>req.destroy(new Error('own loopback timeout')));req.end();});
}
async function info(base) {
 const nonce=randomBytes(16).toString('hex'),hello=await get(base+'/hello',{'x-lma-nonce':nonce});
 assert.equal(hello.status,200);assert.equal(hello.headers['x-lma-proof'],proof('hello:'+nonce));
 const url=new URL(base+'/info'),path=url.pathname,ts=Date.now();
 const result=await get(url.href,{'x-lma-nonce':nonce,'x-lma-auth':`v1 ${ts}.${proof(`req:${nonce}:${ts}:GET:${path}:${digest('')}`)}`});
 assert.equal(result.status,200);assert.equal(result.headers['x-lma-proof-body'],'1');
 assert.equal(result.headers['x-lma-proof'],proof(`resp:${nonce}:GET:${path}:200:${digest(result.body)}`));
 return JSON.parse(result.body.toString());
}
function start(args,env,stdin) {
 const p=spawn(process.execPath,args,{cwd:resolve('.'),env,stdio:['pipe','pipe','pipe']});let stdout='',stderr='';
 p.stdout.on('data',x=>stdout+=x.toString());p.stderr.on('data',x=>stderr+=x.toString());
 const exited=new Promise((ok,bad)=>{p.once('error',bad);p.once('close',code=>ok({code,stdout,stderr}));});
 if(stdin!==undefined)p.stdin.end(stdin);else p.stdin.end();
 return {p,exited,output:()=>({stdout,stderr})};
}
test('production JS used by NodeService ignores QA flags, stays empty/read-only and serves real protected stdio', {timeout:30000},async()=>{
 const home=mkdtempSync(join(tmpdir(),'production-entry-host-')),keyFile=join(home,'client.key');writeFileSync(keyFile,key+'\n',{mode:0o600});
 const owned=start(['android/app/src/main/assets/nodeapp/main.mjs'],{...getDefaultEnvironment(),LINE_MCP_HOME:home,LINE_MCP_PORT:'0',LINE_CONTROL_PORT:'0',LINE_CONNECTOR_PORT:'0',LMA_SECRETS_STDIN:'1',LMA_CONTROL_HMAC_ONLY:'1',LINE_MCP_MOCK:'1',LMA_INCLUDE_MOCK:'1'},JSON.stringify({mcp_token:key,control_token:control,passphrase:'synthetic-production-entry-passphrase'})+'\n');
 let timer;
 const ready=new Promise((ok,bad)=>{timer=setTimeout(()=>bad(new Error('actual production startup timeout')),12000);owned.p.once('error',bad);owned.p.once('exit',()=>bad(new Error('production exited before ready')));owned.p.stdout.on('data',()=>{for(const line of owned.output().stdout.split('\n'))try{const d=JSON.parse(line);if(d.event==='ready'){clearTimeout(timer);ok(d);}}catch{}});});
 try {
  const event=await ready;assert.equal(event.mock,false);assert.equal(event.mcp_error,null);
  const state=await info(event.control);assert.equal(state.mock,false);assert.equal(state.mcp_status,'ready');assert.equal(state.mcp_legacy_http_enabled,false);assert.equal(state.mcp_allow_write,false);
  assert.equal(state.counts.chats,0);assert.equal(state.counts.messages,0);assert.equal(existsSync(join(home,'mock')),false);assert.equal(existsSync(join(home,'line.db')),true);
  const client=start(['scripts/mcp-interop.mjs','--url',state.mcp_secure_url,'--key-file',keyFile],getDefaultEnvironment());
  const timeout=setTimeout(()=>client.p.kill('SIGKILL'),12000);let result;
  try{result=await client.exited;}finally{clearTimeout(timeout);}
  assert.equal(result.code,0,'actual stdio status helper failed');const smoke=JSON.parse(result.stdout);
  assert.equal(smoke.transport,'stdio-adapter');assert.equal(smoke.sync_online,false);assert.equal(smoke.trigger_sync_listed,false);assert.equal(smoke.message_reads_performed,false);
  assert.equal((result.stdout+result.stderr+owned.output().stdout+owned.output().stderr).includes(key),false);
  assert.equal((result.stdout+result.stderr+owned.output().stdout+owned.output().stderr).includes(control),false);
 } finally {clearTimeout(timer);owned.p.kill('SIGTERM');await owned.exited;rmSync(home,{recursive:true,force:true});}
});
