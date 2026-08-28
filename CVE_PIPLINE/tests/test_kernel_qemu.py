import os, sys, subprocess, re, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cve_pipeline.domain.generators import kernel_qemu as Q

P=F=0
def ok(n,c):
    global P,F
    P,F=(P+1,F) if c else (P,F+1); print(("PASS " if c else "FAIL ")+n)

def bash_n(s):
    with tempfile.NamedTemporaryFile("w",suffix=".sh",delete=False) as f: f.write(s); p=f.name
    rc=subprocess.run(["bash","-n",p]).returncode; os.unlink(p); return rc==0

def run(s):
    with tempfile.NamedTemporaryFile("w",suffix=".sh",delete=False) as f: f.write(s); p=f.name
    r=subprocess.run(["bash",p],capture_output=True,text=True); os.unlink(p); return r

def test():
    rel=subprocess.run(["uname","-r"],capture_output=True,text=True).stdout.strip()
    # all three generate valid bash (incl. parens in subsystem)
    ok("verify valid bash", bash_n(Q.verify_script("v6.18.21","crypto/algif_aead (x)",["C"],["s"],["m"],"/opt/cve/poc","true")))
    ok("rootfs valid bash", bash_n(Q.build_rootfs_script(poc_path="/host/poc")))
    ok("launch valid bash", bash_n(Q.launch_script()))
    # verify sentinel logic (strip poweroff so it returns)
    def testable(s): return s.replace("(command -v poweroff >/dev/null && poweroff -f) || echo o > /proc/sysrq-trigger || true","true")
    r=run(testable(Q.verify_script("v"+rel,"t",poc_cmd="touch /tmp/_bt",poc_success="test -f /tmp/_bt"))); os.path.exists("/tmp/_bt") and os.unlink("/tmp/_bt")
    ok("bug present -> VERIFIED sentinel", f"{Q.SENTINEL} VERIFIED" in r.stdout)
    r=run(testable(Q.verify_script("v"+rel,"t",poc_cmd="true",poc_success="test -f /tmp/_none")))
    ok("bug absent -> FAILED sentinel", f"{Q.SENTINEL} FAILED" in r.stdout)
    # launcher grep -> exit code
    launch=Q.launch_script(serial_log="/tmp/_sl.log").replace(': > "$LOG"','# keep')
    launch=re.sub(r"timeout .*?\|\| true","true",launch,flags=re.S)
    for tag,exp in [("VERIFIED",0),("FAILED",1),("none",2)]:
        open("/tmp/_sl.log","w").write(f"{Q.SENTINEL} {tag}\n" if tag!="none" else "panic\n")
        with tempfile.NamedTemporaryFile("w",suffix=".sh",delete=False) as f: f.write(launch); p=f.name
        rc=subprocess.run(["bash",p]).returncode; os.unlink(p)
        ok(f"launcher '{tag}' -> exit {exp}", rc==exp)
    os.path.exists("/tmp/_sl.log") and os.unlink("/tmp/_sl.log")
    print(f"\n{P} passed, {F} failed"); return F

if __name__=="__main__":
    sys.exit(1 if test() else 0)
