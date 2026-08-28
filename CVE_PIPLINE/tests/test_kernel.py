import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cve_pipeline.domain import kernel as K
from cve_pipeline.adapters import osv
from cve_pipeline.evaluation import kernel_resolve as KR

P=F=0
def ok(n,c):
    global P,F
    P,F=(P+1,F) if c else (P,F+1); print(("PASS " if c else "FAIL ")+n)

# CopyFail OSV record (introduced 4.14; fixed 6.18.22 / 6.19.12 / 7.0)
OSV={"affected":[{"ranges":[
 {"type":"GIT","events":[{"introduced":"72548b093ee38a6d4f2a19e6ef1948ae05c181f7"},
   {"fixed":"fafe0fa2995a0f7073c1c358d7d3145bcc9aedd8"},{"fixed":"ce42ee423e58dffa5ec03524054c9d8bfd4f6237"},
   {"fixed":"a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5"}]},
 {"type":"ECOSYSTEM","events":[{"introduced":"4.14"},{"fixed":"6.18.22"},
   {"introduced":"6.19"},{"fixed":"6.19.12"},{"introduced":"6.20"},{"fixed":"7.0"}]}]}]}

def test():
    ok("prev tag 6.18.22->v6.18.21", K.previous_tag("6.18.22")=="v6.18.21")
    ok("branch base 7.0 -> None", K.previous_tag("7.0") is None)
    t=osv.kernel_truth(OSV)
    ok("osv 3 fixed commits", len(t["git_fixed"])==3)
    b=K.branches_from_ranges(t["version_ranges"])
    ok("6.18.x->v6.18.21", any(x["branch"]=="6.18.x" and x["vulnerable_ref"]=="v6.18.21" for x in b))
    ok("7.0 flagged no-ref", any(x["fixed"]=="7.0" and x["vulnerable_ref"] is None for x in b))
    ok("prefer oldest->v6.18.21", K.choose_branch(b,"oldest")[0]["vulnerable_ref"]=="v6.18.21")
    good={"introduced_commit":"72548b093ee38a6d4f2a19e6ef1948ae05c181f7",
          "fixes":[{"version":"6.18.22","commit":"fafe0fa2995a0f7073c1c358d7d3145bcc9aedd8"},
                   {"version":"6.19.12","commit":"ce42ee423e58dffa5ec03524054c9d8bfd4f6237"},
                   {"version":"7.0","commit":"a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5"}]}
    r=KR.resolve(good,t,{"parts":["o"],"products":[{"part":"o","product":"linux_kernel"}]},"6.18.x")
    ok("resolve->v6.18.21", r["vulnerable_ref"]=="v6.18.21")
    ok("full commit recall", r["comparison"]["fixed_commits"]["recall"]==1.0)
    ok("nvd crosscheck kernel", r["comparison"]["nvd_crosscheck"]["is_kernel"] is True)
    bad={"introduced_commit":"72548b093ee3","fixes":[{"version":"6.18.21","commit":None}]}
    rb=KR.resolve(bad,t,None,"6.18.x")
    ok("bad extraction low recall", (rb["comparison"]["fixed_commits"]["recall"] or 0)<1.0)
    print(f"\n{P} passed, {F} failed"); return F

if __name__=="__main__":
    sys.exit(1 if test() else 0)
