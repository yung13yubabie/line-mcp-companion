// Independent defensive validation: synthetic PSKs/messages, self-owned loopback only.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {request} from 'node:http';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport,getDefaultEnvironment} from '@modelcontextprotocol/sdk/client/stdio.js';
import {openDatabase} from '../../src/storage/db.ts';
import {Whitelist} from '../../src/whitelist.ts';
import {startMcpHttp} from '../../src/mcp/server.ts';
import {channelNonce,helloProof,sameProof,sealMcp,openMcp,secureMcpUrl,MCP_REQUEST_LIMIT} from '../../src/mcp/secure-channel.ts';
const KEY='synthetic-independent-mcp-psk-20261126';
const close=s=>new Promise((ok,bad)=>s.close(e=>e?bad(e):ok()));
const root=new URL('../../',import.meta.url).pathname;
function ownHttp(url,method,headers={},body=Buffer.alloc(0)) {
 assert.equal(new URL(url).hostname,'127.0.0.1');
 return new Promise((ok,bad)=>{
  const req=request(url,{method,headers,agent:false},res=>{const chunks=[];res.on('data',x=>chunks.push(x));res.on('error',bad);res.on('end',()=>ok({status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks)}));});
  req.on('error',bad);req.end(body);
 });
}
test('codec binds current key, direction, epoch, nonce, timestamp, response status and bytes',()=>{
 const epoch=channelNonce(),nonce=channelNonce(),ts=Date.now();
 const plain=Buffer.from('{"synthetic_private":"not-a-real-chat"}');
 const sealed=sealMcp(KEY,'response',epoch,nonce,ts,200,plain);
 assert.deepEqual(openMcp(KEY,'response',epoch,nonce,ts,200,sealed),plain);
 assert.equal(sealed.includes(plain),false);assert.equal(sealed.includes(Buffer.from(KEY)),false);
 for(const [key,direction,e,n,t,s] of [[KEY+'-different','response',epoch,nonce,ts,200],[KEY,'request',epoch,nonce,ts,200],[KEY,'response',channelNonce(),nonce,ts,200],[KEY,'response',epoch,channelNonce(),ts,200],[KEY,'response',epoch,nonce,ts+1,200],[KEY,'response',epoch,nonce,ts,201]]) assert.throws(()=>openMcp(key,direction,e,n,t,s,sealed));
 const modified=Buffer.from(sealed);modified[modified.length-1]^=1;
 assert.throws(()=>openMcp(KEY,'response',epoch,nonce,ts,200,modified));
 assert.throws(()=>openMcp(KEY,'response',epoch,nonce,ts,200,sealed.subarray(0,20)));
});
test('request size cap and strict loopback URL configuration fail closed',()=>{
 const e=channelNonce(),n=channelNonce(),t=Date.now();
 const atLimit=Buffer.alloc(MCP_REQUEST_LIMIT,65);
 assert.equal(openMcp(KEY,'request',e,n,t,0,sealMcp(KEY,'request',e,n,t,0,atLimit)).length,MCP_REQUEST_LIMIT);
 assert.throws(()=>sealMcp(KEY,'request',e,n,t,0,Buffer.alloc(MCP_REQUEST_LIMIT+1)));
 assert.equal(secureMcpUrl('http://127.0.0.1:47833/mcp/secure').pathname,'/mcp/secure');
 for(const value of ['http://localhost:47833/mcp/secure','https://127.0.0.1/mcp/secure','http://127.0.0.1/mcp','http://127.0.0.1/mcp/secure?x=1','http://u:p@127.0.0.1/mcp/secure']) assert.throws(()=>secureMcpUrl(value));
});
test('own encrypted mailbox rejects bad tag/replay/expired timestamp and new epoch invalidates old frame',async()=>{
 const store=openDatabase(':memory:');let calls=0;
 const ctx={store,whitelist:new Whitelist(store),sync:{status:()=>{calls++;return {state:'idle'};}},media:null};
 const listener=await startMcpHttp(ctx,{port:0,token:KEY,allowLegacyBearer:false,ratePerMin:1});
 let second;
 try {
  const secure=listener.url+'/secure',challenge=channelNonce();
  const hello=await ownHttp(secure+'/hello','GET',{'x-lma-mcp-challenge':challenge});
  const epoch=hello.headers['x-lma-mcp-epoch'];
  assert.equal(hello.status,204);assert.ok(sameProof(hello.headers['x-lma-mcp-proof'],helloProof(KEY,challenge,epoch)));
  const nonce=channelNonce(),ts=Date.now(),message={jsonrpc:'2.0',id:7,method:'tools/call',params:{name:'get_sync_status',arguments:{}}};
  const frame=sealMcp(KEY,'request',epoch,nonce,ts,0,Buffer.from(JSON.stringify(message)));
  const headers={'content-type':'application/octet-stream','x-lma-mcp-epoch':epoch,'x-lma-mcp-nonce':nonce,'x-lma-mcp-time':String(ts)};
  const bad=Buffer.from(frame);bad[bad.length-1]^=1;
  assert.equal((await ownHttp(secure,'POST',headers,bad)).status,401);assert.equal(calls,0);
  const good=await ownHttp(secure,'POST',headers,frame);
  assert.equal(good.status,200);assert.equal(JSON.parse(openMcp(KEY,'response',epoch,nonce,ts,good.status,good.body)).id,7);assert.equal(calls,1,'failed authentication did not consume the valid fixture nonce');
  assert.equal((await ownHttp(secure,'POST',headers,frame)).status,401);assert.equal(calls,1);
  const freshNonce=channelNonce(),freshTs=Date.now();
  const limited=await ownHttp(secure,'POST',{'content-type':'application/octet-stream','x-lma-mcp-epoch':epoch,'x-lma-mcp-nonce':freshNonce,'x-lma-mcp-time':String(freshTs)},sealMcp(KEY,'request',epoch,freshNonce,freshTs,0,Buffer.from(JSON.stringify(message))));
  assert.equal(limited.status,429);assert.equal(JSON.parse(openMcp(KEY,'response',epoch,freshNonce,freshTs,429,limited.body)),null);assert.equal(calls,1);
  const oldNonce=channelNonce(),oldTs=Date.now()-121000;
  const old=sealMcp(KEY,'request',epoch,oldNonce,oldTs,0,Buffer.from(JSON.stringify(message)));
  assert.equal((await ownHttp(secure,'POST',{'content-type':'application/octet-stream','x-lma-mcp-epoch':epoch,'x-lma-mcp-nonce':oldNonce,'x-lma-mcp-time':String(oldTs)},old)).status,401);
  second=await startMcpHttp(ctx,{port:0,token:KEY,allowLegacyBearer:false});
  assert.equal((await ownHttp(second.url+'/secure','POST',headers,frame)).status,401,'fresh handler startup epoch rejects prior instance frame');
  assert.equal((await ownHttp(listener.url,'POST',{authorization:'Bearer '+KEY,'content-type':'application/json'},Buffer.from('{}'))).status,403,'legacy bearer is explicitly disabled in this application-mode fixture');
 } finally {await close(listener.server);if(second)await close(second.server);store.close();}
});
test('standard SDK stdio entry supports read, deliberate opt-in and next-request downgrade',async()=>{
 const store=openDatabase(':memory:');let polls=0;
 const ctx={store,whitelist:new Whitelist(store),sync:{status:()=>({state:'idle'}),pollOnce:async()=>{polls++;return 0;}},media:null};
 const listener=await startMcpHttp(ctx,{port:0,token:KEY,allowLegacyBearer:false});
 const transport=new StdioClientTransport({command:process.execPath,args:[root+'scripts/mcp-stdio.ts',listener.url+'/secure'],env:{...getDefaultEnvironment(),LMA_MCP_CHANNEL_KEY:KEY},stderr:'pipe',cwd:root});
 let stderr='';transport.stderr?.on('data',x=>{stderr+=x.toString();});
 const client=new Client({name:'independent-stdio-fixture',version:'1'});
 try {
  await client.connect(transport);
  let names=(await client.listTools()).tools.map(x=>x.name);
  assert.ok(names.includes('get_sync_status'));assert.equal(names.includes('trigger_sync'),false);
  const denied=await client.callTool({name:'trigger_sync',arguments:{}});assert.equal(denied.isError,true);assert.equal(polls,0);
  store.setSetting('mcp_allow_write','on');
  names=(await client.listTools()).tools.map(x=>x.name);assert.ok(names.includes('trigger_sync'));
  assert.notEqual((await client.callTool({name:'trigger_sync',arguments:{}})).isError,true);assert.equal(polls,1);
  store.setSetting('mcp_allow_write','off');
  assert.equal((await client.listTools()).tools.some(x=>x.name==='trigger_sync'),false);
  assert.equal((await client.callTool({name:'trigger_sync',arguments:{}})).isError,true);assert.equal(polls,1);
  assert.notEqual((await client.callTool({name:'get_sync_status',arguments:{}})).isError,true);
  assert.equal(stderr.includes(KEY),false);assert.equal(stderr.includes('not-a-real-chat'),false);
 } finally {await client.close();await close(listener.server);store.close();}
});


test('secure mailbox retains the independent send-tool budget',async()=>{
 const store=openDatabase(':memory:');const whitelist=new Whitelist(store);let changes=0;
 store.upsertChat({id:'synthetic-group',type:'GROUP',name:'synthetic group'});whitelist.set('synthetic-group',true);store.setSetting('mcp_allow_write','on');
 const ctx={store,whitelist,sync:null,media:null,ai:{policy:{setTrust:()=>{changes++;return 'review';}}}};
 const listener=await startMcpHttp(ctx,{port:0,token:KEY,allowLegacyBearer:false,sendRatePerMin:1});
 try {
  const secure=listener.url+'/secure',challenge=channelNonce();
  const hello=await ownHttp(secure+'/hello','GET',{'x-lma-mcp-challenge':challenge});const epoch=hello.headers['x-lma-mcp-epoch'];
  const message={jsonrpc:'2.0',id:12,method:'tools/call',params:{name:'set_chat_trust',arguments:{chat_id:'synthetic-group',feature:'ai',state:'REVIEW'}}};
  for(const expected of [200,429]) {
   const nonce=channelNonce(),ts=Date.now();const frame=sealMcp(KEY,'request',epoch,nonce,ts,0,Buffer.from(JSON.stringify(message)));
   const response=await ownHttp(secure,'POST',{'content-type':'application/octet-stream','x-lma-mcp-epoch':epoch,'x-lma-mcp-nonce':nonce,'x-lma-mcp-time':String(ts)},frame);
   assert.equal(response.status,expected);openMcp(KEY,'response',epoch,nonce,ts,expected,response.body);
  }
  assert.equal(changes,1,'the second send-classified request caused no policy mutation');
 } finally {await close(listener.server);store.close();}
});

test('actual application main with fresh synthetic storage defaults to secure stdio and disables legacy HTTP', {timeout:20000}, async()=>{
 const {spawn}=await import('node:child_process');
 const {mkdtempSync,rmSync}=await import('node:fs');const {tmpdir}=await import('node:os');const {join}=await import('node:path');
 const home=mkdtempSync(join(tmpdir(),'lma-own-main-entry-'));
 // Empty storage has no LINE auth token; source entry has no login/sync call in that state.
 const app=spawn(process.execPath,[root+'src/main.ts'],{cwd:root,env:{...getDefaultEnvironment(),LINE_MCP_HOME:home,LINE_MCP_PORT:'0',LINE_CONTROL_PORT:'0',LINE_CONNECTOR_PORT:'0',LMA_INCLUDE_MOCK:'0',LMA_SECRETS_STDIN:'1',LMA_CONTROL_HMAC_ONLY:'1'},stdio:['pipe','pipe','pipe']});
 let stderr='',stdout='';app.stderr.on('data',x=>{stderr+=x.toString();});
 const exited=new Promise(ok=>app.once('exit',ok));
 let startupTimer;
 const ready=new Promise((ok,bad)=>{
  startupTimer=setTimeout(()=>bad(new Error('synthetic application startup timeout')),10000);
  app.on('error',bad);app.once('exit',()=>bad(new Error('synthetic application exited before ready')));
  app.stdout.on('data',chunk=>{
   stdout+=chunk.toString();
   for(const line of stdout.split('\n')) {try {const event=JSON.parse(line);if(event.event==='ready'){clearTimeout(startupTimer);ok(event);}}catch{}}
  });
 });
 app.stdin.end(JSON.stringify({mcp_token:KEY,control_token:'synthetic-separate-control-token-20261126',passphrase:'synthetic-local-only-storage-passphrase'})+'\n');
 let client;
 try {
  const event=await ready;assert.equal(event.mock,false);assert.equal(event.mcp_error,null);
  const legacy=await ownHttp(event.mcp,'POST',{authorization:'Bearer '+KEY,'content-type':'application/json'},Buffer.from('{}'));
  assert.equal(legacy.status,403);
  const transport=new StdioClientTransport({command:process.execPath,args:[root+'scripts/mcp-stdio.ts',event.mcp+'/secure'],env:{...getDefaultEnvironment(),LMA_MCP_CHANNEL_KEY:KEY},stderr:'pipe',cwd:root});
  client=new Client({name:'independent-fresh-main',version:'1'});await client.connect(transport);
  const result=await client.callTool({name:'get_sync_status',arguments:{}});
  assert.notEqual(result.isError,true);assert.equal(JSON.parse(result.content[0].text).online,false);
  assert.equal((await client.listTools()).tools.some(x=>x.name==='trigger_sync'),false);
  assert.equal(stdout.includes(KEY),false);assert.equal(stderr.includes(KEY),false);
 } finally {
  clearTimeout(startupTimer);if(client)await client.close();app.kill('SIGTERM');await exited;rmSync(home,{recursive:true,force:true});
 }
});

test('stdio protected-key-file entry works and refuses broad permissions or symlink', {timeout:15000}, async()=>{
 const {mkdtempSync,writeFileSync,chmodSync,symlinkSync,rmSync}=await import('node:fs');const {tmpdir}=await import('node:os');const {join}=await import('node:path');
 const directory=mkdtempSync(join(tmpdir(),'lma-own-adapter-key-'));const file=join(directory,'key');const link=join(directory,'link');
 writeFileSync(file,KEY+'\n',{mode:0o600});symlinkSync(file,link);
 const store=openDatabase(':memory:');
 const listener=await startMcpHttp({store,whitelist:new Whitelist(store),sync:null,media:null},{port:0,token:KEY,allowLegacyBearer:false});
 async function connect(keyFile,allowed) {
  const transport=new StdioClientTransport({command:process.execPath,args:[root+'scripts/mcp-stdio.ts',listener.url+'/secure'],env:{...getDefaultEnvironment(),LMA_MCP_CHANNEL_KEY_FILE:keyFile},stderr:'pipe',cwd:root});
  let stderr='';transport.stderr?.on('data',x=>{stderr+=x.toString();});
  const client=new Client({name:'independent-keyfile-fixture',version:'1'});
  try {
   if(allowed){await client.connect(transport);assert.ok((await client.listTools()).tools.length>0);}
   else await assert.rejects(client.connect(transport));
   assert.equal(stderr.includes(KEY),false);
  } finally {await client.close();}
 }
 try {
  await connect(file,true);
  chmodSync(file,0o644);await connect(file,false);
  chmodSync(file,0o600);await connect(link,false);
 } finally {await close(listener.server);store.close();rmSync(directory,{recursive:true,force:true});}
});
