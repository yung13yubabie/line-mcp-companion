/** Actual host main + authenticated Control + real SDK stdio adapter. Fresh synthetic-only storage;
 * no saved LINE token, no login, no mocked Android/device acceptance and no message-reading tools. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { request } from 'node:http';
import { getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js';
const ROOT=resolve('.'), KEY='synthetic-mcp-migration-key-20261127', CONTROL='synthetic-control-migration-key-20261127';
const hash=(data:Buffer|string)=>createHash('sha256').update(data).digest('hex');
const proof=(message:string)=>createHmac('sha256',CONTROL).update(message).digest('hex');
function http(url:string,headers:Record<string,string>={}) {
 return new Promise<{status:number;headers:import('node:http').IncomingHttpHeaders;body:Buffer}>((ok,bad)=>{
  const req=request(url,{headers,method:'GET',timeout:5000},res=>{const chunks:Buffer[]=[];res.on('data',x=>chunks.push(x));res.on('end',()=>ok({status:res.statusCode??0,headers:res.headers,body:Buffer.concat(chunks)}));});
  req.on('error',bad);req.on('timeout',()=>req.destroy(new Error('own loopback timeout')));req.end();
 });
}
async function controlInfo(base:string) {
 const nonce=randomBytes(16).toString('hex');
 const hello=await http(base+'/hello',{'x-lma-nonce':nonce});assert.equal(hello.status,200);assert.equal(hello.headers['x-lma-proof'],proof('hello:'+nonce));
 const url=new URL(base+'/info'), path=url.pathname,ts=Date.now();
 const result=await http(url.href,{'x-lma-nonce':nonce,'x-lma-auth':`v1 ${ts}.${proof(`req:${nonce}:${ts}:GET:${path}:${hash('')}`)}`});
 assert.equal(result.status,200);assert.equal(result.headers['x-lma-proof-body'],'1');assert.equal(result.headers['x-lma-proof'],proof(`resp:${nonce}:GET:${path}:200:${hash(result.body)}`));
 return JSON.parse(result.body.toString());
}
async function command(args:string[],env:Record<string,string>) {
 const child=spawn(process.execPath,args,{cwd:ROOT,env,stdio:['ignore','pipe','pipe']});let stdout='',stderr='';
 child.stdout.on('data',x=>stdout+=x.toString());child.stderr.on('data',x=>stderr+=x.toString());
 const timeout=setTimeout(()=>child.kill('SIGKILL'),15000);
 try {const code=await new Promise<number|null>((ok,bad)=>{child.once('exit',ok);child.once('error',bad);});return{code,stdout,stderr};}finally{clearTimeout(timeout);}
}
for(const legacy of [false,true])test(`actual host main advertises the usable stdio endpoint and legacy state (${legacy?'explicit isolated opt-in':'default disabled'})`,{timeout:25000},async()=>{
 const home=mkdtempSync(join(tmpdir(),'lma-mcp-migration-')),keyFile=join(home,'client-mcp.key');writeFileSync(keyFile,KEY+'\n',{mode:0o600});
 const env={...getDefaultEnvironment(),LINE_MCP_HOME:home,LINE_MCP_PORT:'0',LINE_CONTROL_PORT:'0',LINE_CONNECTOR_PORT:'0',LMA_INCLUDE_MOCK:'0',LMA_SECRETS_STDIN:'1',LMA_CONTROL_HMAC_ONLY:'1',...(legacy?{LMA_MCP_LEGACY_HTTP:'1'}:{})};
 const child=spawn(process.execPath,['src/main.ts'],{cwd:ROOT,env,stdio:['pipe','pipe','pipe']});let stdout='',stderr='';child.stderr.on('data',x=>stderr+=x.toString());const exited=new Promise(ok=>child.once('exit',ok));
 let timer:ReturnType<typeof setTimeout>;
 const ready=new Promise<{mock:boolean;mcp:string;control:string;mcp_error:null}>((ok,bad)=>{timer=setTimeout(()=>bad(new Error('fresh own main startup timeout')),10000);child.once('error',bad);child.once('exit',()=>bad(new Error('fresh own main exited before ready')));child.stdout.on('data',x=>{stdout+=x.toString();for(const line of stdout.split('\n'))try{const d=JSON.parse(line);if(d.event==='ready'){clearTimeout(timer);ok(d);}}catch{}});});
 child.stdin.end(JSON.stringify({mcp_token:KEY,control_token:CONTROL,passphrase:'synthetic-migration-storage-passphrase'})+'\n');
 try {
  const event=await ready;assert.equal(event.mock,false);assert.equal(event.mcp_error,null);
  const info=await controlInfo(event.control);assert.equal(info.mcp_status,'ready');assert.equal(info.mcp_url,event.mcp);assert.equal(info.mcp_secure_url,event.mcp+'/secure');assert.notEqual(new URL(info.mcp_secure_url).port,'0');
  assert.equal(info.mcp_legacy_http,legacy);assert.equal(info.mcp_legacy_http_enabled,legacy);assert.equal(info.transport,'stdio-adapter');assert.equal(info.mcp_auth,'mcp-psk-aead-v1');
  assert.equal((await http(event.mcp)).status,legacy?401:403);
  const smoke=await command(['scripts/mcp-interop.mjs','--url',info.mcp_secure_url,'--key-file',keyFile],getDefaultEnvironment());assert.equal(smoke.code,0,'real stdio helper failed');
  const result=JSON.parse(smoke.stdout.trim());assert.equal(result.transport,'stdio-adapter');assert.equal(result.sync_online,false);assert.ok(result.tool_count>0);assert.equal(result.trigger_sync_listed,false);assert.equal(result.message_reads_performed,false);
  assert.equal((stdout+stderr+smoke.stdout+smoke.stderr).includes(KEY),false);assert.equal((stdout+stderr+smoke.stdout+smoke.stderr).includes(CONTROL),false);
 } finally {clearTimeout(timer!);child.kill('SIGTERM');await exited;rmSync(home,{recursive:true,force:true});}
});
test('retired HTTP/argv-key helper syntax fails closed without echoing credentials or connecting',async()=>{
 const result=await command(['scripts/mcp-interop.mjs','retired-positional-mode',KEY],getDefaultEnvironment());assert.equal(result.code,64);assert.equal((result.stdout+result.stderr).includes(KEY),false);
});
test('synthetic host fixture advertises only protected stdio and cleans its own key file', {timeout:25000}, async()=>{
 const child=spawn(process.execPath,['scripts/serve-fake.ts'],{cwd:ROOT,env:getDefaultEnvironment(),stdio:['ignore','pipe','pipe']});
 let stdout='',stderr='',timer:ReturnType<typeof setTimeout>, keyFile:string|undefined;
 child.stderr.on('data',x=>stderr+=x.toString());const exited=new Promise(ok=>child.once('exit',ok));
 const ready=new Promise<{scope:string;mcp_secure_url:string;mcp_legacy_http_enabled:boolean;key_file:string}>((ok,bad)=>{
  timer=setTimeout(()=>bad(new Error('own synthetic fixture startup timeout')),10000);
  child.once('error',bad);child.once('exit',()=>bad(new Error('fixture exited before ready')));
  child.stdout.on('data',x=>{stdout+=x.toString();for(const line of stdout.split('\n'))try{const d=JSON.parse(line);if(d.event==='ready'){clearTimeout(timer);ok(d);}}catch{}});
 });
 try {
  const event=await ready;keyFile=event.key_file;assert.equal(event.scope,'synthetic-host-fixture');assert.equal(event.mcp_legacy_http_enabled,false);
  assert.notEqual(new URL(event.mcp_secure_url).port,'0');assert.equal((await http(event.mcp_secure_url.replace(/\/secure$/,''))).status,403);
  const result=await command(['scripts/mcp-interop.mjs','--url',event.mcp_secure_url,'--key-file',keyFile],getDefaultEnvironment());
  assert.equal(result.code,0);const smoke=JSON.parse(result.stdout);assert.equal(smoke.transport,'stdio-adapter');assert.equal(smoke.message_reads_performed,false);assert.equal(smoke.trigger_sync_listed,false);
  assert.equal((stdout+stderr).includes('Authorization:'),false);
 } finally {clearTimeout(timer!);child.kill('SIGTERM');await exited;}
 if(keyFile)assert.equal(existsSync(keyFile),false,'fixture must remove only its own temporary key');
});
