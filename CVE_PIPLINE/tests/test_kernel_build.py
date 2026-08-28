import os, sys, subprocess, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cve_pipeline.domain.generators.kernel_build import build_kernel_script, _norm
from cve_pipeline.kernel_repro import emit_kernel_scripts

P=F=0
def ok(n,c):
    global P,F
    P,F=(P+1,F) if c else (P,F+1); print(("PASS " if c else "FAIL ")+n)
def bash_n(s):
    with tempfile.NamedTemporaryFile("w",suffix=".sh",delete=False) as f: f.write(s); p=f.name
    rc=subprocess.run(["bash","-n",p]).returncode; os.unlink(p); return rc==0

def test():
    ok("CONFIG_ prefix stripped", _norm("CONFIG_X")=="X" and _norm("X")=="X")
    b=build_kernel_script("v6.18.21",["CONFIG_CRYPTO_USER_API_AEAD"],"crypto/algif_aead")
    ok("build valid bash", bash_n(b))
    ok("shallow clone at tag", '--depth 1 --branch "$REF"' in b)
    ok("kvm_guest.config with fallback", "kvm_guest.config" in b and "kvmconfig" in b)
    ok("forces serial+virtio+ext4", all(x in b for x in ["SERIAL_8250_CONSOLE","VIRTIO_BLK","EXT4_FS"]))
    ok("forces CVE subsystem =y (built-in)", "--enable CRYPTO_USER_API_AEAD" in b)
    ok("verifies options stuck", "did not stick" in b and "olddefconfig" in b)
    ok("builds bzImage", "make -j$(nproc) bzImage" in b)

    work=tempfile.mkdtemp()
    try:
        w=emit_kernel_scripts("CVE-2026-31431","v6.18.21",os.path.join(work,"machines"),
            config_options=["CONFIG_CRYPTO_USER_API_AEAD"],subsystem="crypto/algif_aead",
            poc_cmd="/host/poc",poc_success="test -f /root/BUG")
        ok("emits 4 scripts", len(w)==4 and all(os.path.exists(p) for p in w.values()))
        ok("all valid bash", all(subprocess.run(["bash","-n",p]).returncode==0 for p in w.values()))
        ok("build/launch agree on virtio /dev/vda",
           "if=virtio" in open(w["run_qemu.sh"]).read() and "VIRTIO_BLK" in open(w["build_kernel.sh"]).read())
    finally:
        shutil.rmtree(work)
    print(f"\n{P} passed, {F} failed"); return F

if __name__=="__main__":
    sys.exit(1 if test() else 0)
