from pathlib import Path
import contextlib,copy,hashlib,importlib.util,io,json,os,tempfile
from unittest.mock import patch
root=Path(__file__).resolve().parents[3];source=root/"scripts/review-apk.py";h=hashlib.sha256(source.read_bytes()).hexdigest();assert h=="161df3d7ed91720092363d70d586588fa0678a0ec9362317b5a14626fff51de6"
s=importlib.util.spec_from_file_location("independent_review_apk",source);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
out=Path(__file__).resolve().parent;cases=[]
def case(name,fn):
 try:fn();cases.append({"case":name,"pass":True})
 except Exception as e:cases.append({"case":name,"pass":False,"error":repr(e)})
def check(value):assert value
def rejects(sig,badging):
 try:m.parse_inspection(sig,badging)
 except m.Blocked:return
 raise AssertionError("malformed metadata accepted")
sig=(root/"build/audit/independent-new-ci/x86_64-signature.txt").read_text();badging=(root/"build/audit/independent-new-ci/x86_64-package.txt").read_text()
for cohort,folder in [("original",root/"build/input/pr11"),("new",root/"build/audit/independent-new-ci")]:
 for abi in ["arm64-v8a","x86_64"]:
  case("parse existing official raw outputs:"+cohort+":"+abi,lambda folder=folder,abi=abi:check(m.parse_inspection((folder/(abi+"-signature.txt")).read_text(),(folder/(abi+"-package.txt")).read_text())["abi"]==abi))
old=m.parse_inspection((root/"build/input/pr11/x86_64-signature.txt").read_text(),(root/"build/input/pr11/x86_64-package.txt").read_text());new=m.parse_inspection(sig,badging)
case("historical actual signer difference and same version both block",lambda:check(set(m.compare_conditions(old,new))=={"signer_mismatch","version_not_advanced"}))
for label,b in [("SDK malformed duplicate",badging+"sdkVersion:'99' extra\n"),("native ABI malformed duplicate",badging+"native-code: malformed\n"),("target SDK malformed duplicate",badging+"targetSdkVersion:'not-a-number' extra\n"),("package duplicate malformed",badging+"package: ignored malformed\n"),("major version unsupported",badging.replace("versionCode='5'","versionCode='5' versionCodeMajor='1'")),("split unsupported",badging.replace("versionCode='5'","versionCode='5' split='config.x86_64'")),("zero version",badging.replace("versionCode='5'","versionCode='0'")),("negative version",badging.replace("versionCode='5'","versionCode='-1'")),("noninteger version",badging.replace("versionCode='5'","versionCode='5.1'")),("overrange version",badging.replace("versionCode='5'","versionCode='2147483648'")),("multiple ABI",badging.replace("native-code: 'x86_64'","native-code: 'x86_64' 'arm64-v8a'")),("non-Review package",badging.replace("tw.linemcp.app.review","tw.linemcp.app"))]:
 case(label,lambda b=b:rejects(sig,b))
for label,sig2 in [("malformed duplicate signer count",sig+"Number of signers malformed\n"),("malformed duplicate certificate",sig+"Signer #1 certificate SHA-256 digest malformed\n"),("malformed duplicate required scheme",sig+"Verified using v2 scheme unknown\n"),("unknown signature scheme",sig+"Verified using v5 scheme (unknown): true\n"),("malformed optional scheme",sig+"Verified using v4 scheme (broken): perhaps\n"),("extra signer",sig+"Signer #2 certificate SHA-256 digest: "+"a"*64+"\n"),("unknown signer spelling",sig+"Signer #? certificate SHA-256 digest: unknown\n"),("rotation unsupported",sig+"Proof of rotation: present\n"),("duplicate verifies",sig+"Verifies\n")]:
 case(label,lambda sig2=sig2:rejects(sig2,badging))
for name,changes,reason in [("same version",{"versionCode":5},"version_not_advanced"),("downgrade",{"versionCode":4},"version_not_advanced"),("ABI mismatch",{"versionCode":6,"abi":"arm64-v8a"},"abi_mismatch"),("signer mismatch",{"versionCode":6,"certificate_sha256":"a"*64},"signer_mismatch")]:
 candidate={**new,**changes};case("synthetic decision:"+name,lambda candidate=candidate,reason=reason:check(reason in m.compare_conditions(new,candidate)))
with tempfile.TemporaryDirectory(dir=out) as d:
 t=Path(d);tools=t/"tools";tools.mkdir()
 for name in ["aapt","apksigner"]:(tools/name).write_bytes(b"NEVER EXECUTED synthetic stub");(tools/name).chmod(0o700)
 base=t/"base.apk";cand=t/"candidate.apk";base.write_bytes(b"synthetic base");cand.write_bytes(b"synthetic candidate")
 def run(change=False):
  base.write_bytes(b"synthetic base");cand.write_bytes(b"synthetic candidate");report=t/"compare.json"
  def fake(tool,args):
   candidate=Path(args[-1]).read_bytes()==b"synthetic candidate"
   if candidate and change:base.write_bytes(b"synthetic baseline changed after completed baseline inspect")
   return {"exit_code":0,"output":sig if tool.name=="apksigner" else badging.replace("versionCode='5'","versionCode='6'") if candidate else badging}
  with patch.object(m,"run_tool",side_effect=fake),contextlib.redirect_stdout(io.StringIO()):code=m.main(["compare","--build-tools",str(tools),"--baseline",str(base),"--candidate",str(cand),"--report",str(report)])
  result=json.loads(report.read_text())
  if change:check(code!=0 and result["upgrade_decision"]=="blocked" and any("changed" in x for x in result["blocked_reasons"]))
  else:
   check(code==0 and result["upgrade_decision"]=="eligible_for_authorized_isolated_upgrade_test");check(all(v=="not_tested" for v in result["scope"].values()))
 case("synthetic wrapper: same signer advancing version is only future-test eligibility",lambda:run(False))
 case("synthetic wrapper: baseline changes after its inspection blocks aggregate decision",lambda:run(True))
 base.write_bytes(b"synthetic base");alias=t/"alias.json";os.link(base,alias);link=t/"link.json";link.symlink_to(base)
 for label,report in [("hardlink",alias),("symlink",link)]:
  def protected(report=report):
   original=base.read_bytes()
   with patch.object(m,"inspect_apk") as inspect,contextlib.redirect_stdout(io.StringIO()):code=m.main(["inspect","--build-tools",str(tools),"--apk",str(base),"--report",str(report)])
   check(code!=0 and base.read_bytes()==original);inspect.assert_not_called()
  case("synthetic report protection:"+label,protected)
r={"scope":"Independent parse/decision/file-consistency cases; official historical text inputs and mocked-wrapper synthetic fixtures, no APK signing, installation or Android execution","source_sha256":h,"source_unchanged":h==hashlib.sha256(source.read_bytes()).hexdigest(),"passed":sum(x["pass"] for x in cases),"total":len(cases),"cases":cases}
(out/"after-independent-cases.json").write_text(json.dumps(r,indent=2)+"\n");print(json.dumps(r,indent=2));assert r["passed"]==r["total"] and r["source_unchanged"]
