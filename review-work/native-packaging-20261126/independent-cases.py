import hashlib,importlib.util,json,struct,sys
from pathlib import Path
root=Path(__file__).resolve().parents[2]
parser_hash_before=hashlib.sha256((root/"scripts/node-android/native-runtime.py").read_bytes()).hexdigest()
spec=importlib.util.spec_from_file_location("audit_native",root/"scripts/node-android/native-runtime.py");m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
lock=json.loads((root/"android/native-runtime.lock.json").read_text());results=[]
def patch_ph(data,kind,field,value):
 b=bytearray(data);off=struct.unpack_from("<Q",b,32)[0];sz,n=struct.unpack_from("<HH",b,54)
 for i in range(n):
  if struct.unpack_from("<I",b,off+i*sz)[0]==kind:struct.pack_into("<Q",b,off+i*sz+field,value);return bytes(b)
 raise AssertionError("missing PHDR")
def replace(data,old,new):
 assert len(old)==len(new);assert old in data
 return data.replace(old,new,1)
def case(name,fn,reject=False):
 try:
  fn();results.append({"case":name,"expected":"reject" if reject else "accept","observed":"accept","pass":not reject})
 except RuntimeError as e:results.append({"case":name,"expected":"reject" if reject else "accept","observed":"reject","reason":str(e),"pass":reject})
for abi in ["arm64-v8a","x86_64"]:
 libs={p.name:p.read_bytes() for p in (root/"build/audit/elfs"/abi).glob("*.so")};names=set(lock["outputs"][abi])
 case(abi+":original actual fixed APK graph",lambda:m.verify_linkage(libs,names,abi))
 def changed(name,fn):
  graph=dict(libs);graph[name]=fn(graph[name]);return m.verify_linkage(graph,names,abi)
 def entry(data,value):
  b=bytearray(data);struct.pack_into("<Q",b,24,value);return bytes(b)
 case(abi+":zero executable entry",lambda:changed("libnode.so",lambda b:entry(b,0)),True)
 case(abi+":out-of-LOAD executable entry",lambda:changed("libnode.so",lambda b:entry(b,0x7fff000000000000)),True)
 case(abi+":shared library executable entry",lambda:changed("libtx_ssl.so",lambda b:entry(b,512)),True)
 case(abi+":unsafe runtime search path",lambda:changed("libnode.so",lambda b:replace(b,b"$ORIGIN\0",b"/unsafe\0")),True)
 case(abi+":incorrect Android interpreter",lambda:changed("libnode.so",lambda b:replace(b,b"/system/bin/linker64\0",b"/system/bin/linker99\0")),True)
 case(abi+":missing exact-provider version",lambda:changed("libtx_crypto.so",lambda b:replace(b,b"OPENSSL_3.6.0\0",b"OPENSSL_9.6.0\0")),True)
 case(abi+":dynamic virtual address outside mapped LOADs",lambda:changed("libnode.so",lambda b:patch_ph(b,2,16,0x7fff000000000000)),True)
 case(abi+":dynamic mapping disagrees with file offset",lambda:changed("libnode.so",lambda b:patch_ph(b,2,16,0x100)),True)
 case(abi+":dynamic memory smaller than file extent",lambda:changed("libnode.so",lambda b:patch_ph(b,2,40,1)),True)
def relro_fixture(load_mem,relro_mem,other=False):
 b=bytearray(4096);b[:7]=b"\x7fELF\x02\x01\x01";struct.pack_into("<HHI",b,16,3,183,1);struct.pack_into("<Q",b,32,64);struct.pack_into("<HHH",b,52,64,56,3 if other else 2)
 struct.pack_into("<IIQQQQQQ",b,64,1,6,0,0x4000,0,load_mem,load_mem,16384)
 struct.pack_into("<IIQQQQQQ",b,120,0x6474e552,4,0,0x4000,0,relro_mem,relro_mem,1)
 if other:struct.pack_into("<IIQQQQQQ",b,176,1,6,0x800,0x4800,0,0,0x100,16384)
 return bytes(b)
case("synthetic:RELRO padding extends beyond used LOAD",lambda:m.elf_machine(relro_fixture(0x300,0x500)))
case("synthetic:RELRO protection tail covers same-LOAD data",lambda:m.elf_machine(relro_fixture(0x1000,0x500)),True)
case("synthetic:RELRO protection tail covers separate-LOAD BSS",lambda:m.elf_machine(relro_fixture(0x300,0x500,True)),True)
out={"scope":"Independent static in-memory ELF contract cases; no Android/native execution, downloads, or production changes","parser_sha256":parser_hash_before,"parser_source_unchanged_during_cases":parser_hash_before==hashlib.sha256((root/"scripts/node-android/native-runtime.py").read_bytes()).hexdigest(),"cases":results,"passed":sum(x["pass"] for x in results),"total":len(results)}
p=root/"build/audit"/(sys.argv[1] if len(sys.argv)>1 else "independent-patch-cases.json");p.write_text(json.dumps(out,indent=2)+"\n");print(json.dumps(out,indent=2))
