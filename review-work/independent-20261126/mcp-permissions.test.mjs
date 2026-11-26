// Standard MCP Client + authenticated control API, synthetic loopback fixtures only.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHash,createHmac} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {openDatabase} from '../../src/storage/db.ts';
import {Whitelist} from '../../src/whitelist.ts';
import {startMcpHttp} from '../../src/mcp/server.ts';
import {startControlHttp} from '../../src/control/server.ts';
const TOKEN='synthetic-independent-token-20261126';
const close=s=>new Promise((ok,bad)=>s.close(e=>e?bad(e):ok()));
const sha=x=>createHash('sha256').update(x).digest('hex');
async function permission(url,enabled) {
 assert.equal(new URL(url).hostname,'127.0.0.1');
 const path='/control/mcp/permissions';
 const body=JSON.stringify({mcp_allow_write:enabled});
 const nonce=randomBytes(16).toString('hex'),ts=Date.now();
 const mac=createHmac('sha256',TOKEN).update(`req:${nonce}:${ts}:POST:${path}:${sha(body)}`).digest('hex');
 const r=await fetch(url+'/mcp/permissions',{method:'POST',headers:{'content-type':'application/json','x-lma-nonce':nonce,'x-lma-auth':`v1 ${ts}.${mac}`},body});
 assert.equal(r.status,200);
 assert.equal((await r.json()).mcp_allow_write,enabled);
}
async function denied(client) {
 let rejected=false;
 try {const r=await client.callTool({name:'trigger_sync',arguments:{}});rejected=r.isError===true;} catch {rejected=true;}
 assert.equal(rejected,true,'direct write tool call must be refused');
}
test('local MCP defaults read-only, explicit control opt-in enables write, next request honors revocation',async()=>{
 const store=openDatabase(':memory:');
 const whitelist=new Whitelist(store);
 let polls=0;
 const sync={pollOnce:async()=>{polls++;return 0;},status:()=>({state:'idle'})};
 const mcp=await startMcpHttp({store,whitelist,sync,media:null},{port:0,token:TOKEN});
 const control=await startControlHttp({store,whitelist,login:()=>({phase:'logged_out'}),startQrLogin:()=>{}},{port:0,token:TOKEN,hmacOnly:true});
 const client=new Client({name:'independent-synthetic-audit',version:'1'});
 try {
  assert.equal(new URL(mcp.url).hostname,'127.0.0.1');
  await client.connect(new StreamableHTTPClientTransport(new URL(mcp.url),{requestInit:{headers:{authorization:`Bearer ${TOKEN}`}}}));
  let names=(await client.listTools()).tools.map(x=>x.name);
  assert.ok(names.includes('get_sync_status'));
  assert.equal(names.includes('trigger_sync'),false);
  await denied(client);assert.equal(polls,0);
  await permission(control.url,true);
  names=(await client.listTools()).tools.map(x=>x.name);
  assert.ok(names.includes('trigger_sync'));
  const result=await client.callTool({name:'trigger_sync',arguments:{}});
  assert.notEqual(result.isError,true);assert.equal(polls,1);
  await permission(control.url,false);
  names=(await client.listTools()).tools.map(x=>x.name);
  assert.equal(names.includes('trigger_sync'),false);
  await denied(client);assert.equal(polls,1,'no new side effects after downgrade');
  const read=await client.callTool({name:'get_sync_status',arguments:{}});
  assert.notEqual(read.isError,true,'read remains available after downgrade');
 } finally {await client.close();await close(mcp.server);await close(control.server);store.close();}
});
