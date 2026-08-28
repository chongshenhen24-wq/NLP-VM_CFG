import os, sys, subprocess, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cve_pipeline.domain.generators.kernel_verify import build_verify

P=F=0
def ok(n,c):
    global P,F
    P,F=(P+1,F) if c else (P,F+1); print(("PASS " if c else "FAIL ")+n)

def run(script):
    with tempfile.NamedTemporaryFile("w",suffix=".sh",delete=False) as f:
        f.write(script); path=f.name
    # syntax must be valid
    syn=subprocess.run(["bash","-n",path])
    r=subprocess.run(["bash",path],capture_output=True,text=True)
    os.unlink(path)
    return syn.returncode, r.returncode, r.stdout

def test():
    rel=subprocess.run(["uname","-r"],capture_output=True,text=True).stdout.strip()
    # parens in subsystem must not break syntax (the bug running caught)
    syn,_,_=run(build_verify("v6.18.21","crypto/algif_aead (aead)",["CONFIG_X"],["algif_aead"],["algif_aead"],"/bin/false","false"))
    ok("valid bash even with parens in subsystem", syn==0)
    # wrong kernel -> exit 1
    _,rc,out=run(build_verify("v0.0.0-nonexistent"))
    ok("wrong kernel -> non-zero exit", rc!=0)
    ok("wrong kernel -> RESULT FAILED", "verification FAILED" in out)
    # matching kernel + marker PoC -> exit 0
    _,rc,out=run(build_verify("v"+rel, poc_cmd="true", poc_success="true"))
    ok("matching kernel + poc pass -> exit 0", rc==0)
    ok("matching -> RESULT VERIFIED", "VERIFIED" in out)
    print(f"\n{P} passed, {F} failed"); return F

if __name__=="__main__":
    sys.exit(1 if test() else 0)
