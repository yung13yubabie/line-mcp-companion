// Independent tests exercise only synthetic values and an in-memory console sink.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {installSafeConsole} from '../../src/control/safe-console.ts';
test('formatted object, Error, interpolation and rotated current secrets are redacted',()=>{
 const output=[];
 const fake=Object.fromEntries(['log','error','warn','info'].map(k=>[k,(...x)=>output.push(x.join(' '))]));
 let secrets=['synthetic-current-mcp-token-20261126'];
 const restore=installSafeConsole(fake,()=>secrets);
 try {
  fake.log({nested:{token:secrets[0]},okay:17});
  fake.error(new Error('synthetic failure '+secrets[0]));
  fake.warn('value=%s',secrets[0]);
  secrets=['synthetic-rotated-mcp-token-20261126'];
  fake.info({rotated:secrets[0]});
  for(const line of output) assert.equal(line.includes('mcp-token-20261126'),false);
  assert.ok(output.every(x=>x.includes('[redacted]')));
  assert.ok(output[0].includes('17'),'nonsecret diagnostics remain useful');
 } finally {restore();}
 fake.log('restored');
 assert.equal(output.at(-1),'restored');
});
test('inspection does not execute custom inspectors/getters and output is bounded',()=>{
 const output=[];
 const fake=Object.fromEntries(['log','error','warn','info'].map(k=>[k,(x)=>output.push(x)]));
 let calls=0;
 const inspectSymbol=Symbol.for('nodejs.util.inspect.custom');
 const obj={get hidden(){calls++;return 'unexpected';},[inspectSymbol](){calls++;return 'unexpected';}};
 const restore=installSafeConsole(fake,()=>[]);
 try {
  fake.log(obj);
  fake.error('x'.repeat(20000));
  assert.equal(calls,0);
  assert.ok(output[1].length<=8193,'log cap plus ellipsis');
 } finally {restore();}
});
