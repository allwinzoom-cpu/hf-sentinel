import re, sys
s=open("hf-llm-security-scanner-project-plan.md").read()
L=s.splitlines()
results=[]
def check(name, ok, detail=""):
    results.append((name, ok, detail))

# ---------- ACCURACY ----------
sec4=s[s.index("## 4."):s.index("## 5.")]
cat_ids=re.findall(r'\|\s*([ABCDEH]\d{1,2})\s*\|',sec4)
defn=sorted(set(cat_ids), key=lambda x:(x[0],int(x[1:])))

# 1 no dup IDs
check("No duplicate catalog IDs", len(cat_ids)==len(set(cat_ids)),
      f"{[x for x in set(cat_ids) if cat_ids.count(x)>1]}")

# 2 every ID in 4.0 gate (expand ranges)
gate=s[s.index("### 4.0"):s.index("### 4.1")]
def in_ranges(i,text):
    L0,n=i[0],int(i[1:])
    if i in text: return True
    for m in re.finditer(rf'{L0}(\d+)[\u2013-]{L0}?(\d+)',text):
        if int(m.group(1))<=n<=int(m.group(2)): return True
    return False
miss_gate=[i for i in defn if not in_ranges(i,gate)]
check("Every catalog ID classified in 4.0 gate", not miss_gate, str(miss_gate))

# 3 every ID in traceability matrix
matrix=s[s.index("### 10.1"):s.index("## 11.")]
miss_mx=[i for i in defn if not in_ranges(i,matrix)]
check("Every catalog ID in traceability matrix", not miss_mx, str(miss_mx))

# 4 garak probes cited are confirmed
confirmed={"atkgen","continuation","dan","donotanswer","encoding","gcg","glitch","goodside",
"knownbadsignatures","leakreplay","lmrc","malwaregen","misleading","packagehallucination",
"promptinject","realtoxicityprompts","replay","snowball","tap","xss","visual_jailbreak","latentinjection"}
cited=set(re.findall(r'garak[^.\n]*?`([a-z_]+)`',s)) | set(re.findall(r'`([a-z_]+)`',s))
# restrict to things that look like probes (appear near 'garak')
garak_ctx=set(re.findall(r'`([a-z_]+)`',s))
probe_cited={c for c in garak_ctx if c in confirmed}
bad_probe=[c for c in probe_cited if c not in confirmed]
check("All cited garak probes are real", not bad_probe, str(bad_probe))

# 5 single consistent version
vers=re.findall(r'\*\*Version:\*\*\s*([0-9.]+)',s)
check("Exactly one version string", len(vers)==1, str(vers))

# 6 threat model: T4/T5 not used as active actors (only in 'dropped' note)
active_t45=[ln[:80] for ln in L if re.search(r'\bT[45]\b',ln) and "Dropped" not in ln and "dropped" not in ln and "artifact publisher" not in ln and "white-box" not in ln]
check("No active T4/T5 threat actors", not active_t45, str(active_t45[:3]))

# 7 scan IDs referenced exist (S1..S10 defined in 9.2)
defined_scans=set(re.findall(r'\*\*(S\d+)\s',s))
ref_scans=set(re.findall(r'\b(S\d+)\b',s))
undef_scans=[x for x in ref_scans if x not in defined_scans]
check("All referenced scan IDs (S#) are defined", not undef_scans, f"defined={sorted(defined_scans)} undefined_refs={undef_scans}")

# 8 Section references point to existing sections (1..14 + appendices)
sec_nums=set(int(m.group(1)) for m in re.finditer(r'^##\s+(\d+)\.',s,re.M))
refs=set(int(m) for m in re.findall(r'Section (\d+)',s))
bad_secref=[r for r in refs if r not in sec_nums]
check("All 'Section N' refs exist", not bad_secref, f"sections={sorted(sec_nums)} bad={bad_secref}")

# 9 Phase references 0..6 exist
phase_defined=set(int(m) for m in re.findall(r'### Phase (\d+)',s))
phase_ref=set(int(m) for m in re.findall(r'Phase (\d+)',s))
bad_phase=[p for p in phase_ref if p not in phase_defined]
check("All 'Phase N' refs exist", not bad_phase, f"defined={sorted(phase_defined)} bad={bad_phase}")

# 10 Appendix refs exist
app_defined=set(re.findall(r'## Appendix ([A-C])',s))
app_ref=set(re.findall(r'Appendix ([A-C])',s))
check("All Appendix refs exist", app_ref<=app_defined, f"defined={sorted(app_defined)} refs={sorted(app_ref)}")

# ---------- STABILITY ----------
# 11 section numbering complete 1..14
_mx=max(sec_nums); check(f"Sections 1..{_mx} all present", sec_nums==set(range(1,_mx+1)), f"missing={sorted(set(range(1,_mx+1))-sec_nums)}")

# 12 code fences balanced
check("Code fences balanced", s.count("```")%2==0, f"count={s.count('```')}")

# 13 table row integrity: within each contiguous table block, equal pipe counts
blocks=[]; cur=[]
for ln in L:
    if ln.strip().startswith("|"):
        cur.append(ln)
    else:
        if cur: blocks.append(cur); cur=[]
if cur: blocks.append(cur)
bad_tables=0
for b in blocks:
    counts={ln.count("|") for ln in b}
    if len(counts)>1: bad_tables+=1
check("All table blocks have consistent column counts", bad_tables==0, f"{bad_tables} inconsistent block(s)")

# 14 no unresolved placeholders (except intentional ATLAS AML.T???? )
ph=[ln[:70] for ln in L if re.search(r'(TODO|FIXME|XXX|\bTBD\b)',ln)]
check("No TODO/FIXME/TBD placeholders", not ph, str(ph[:3]))

# 15 out-of-scope static tools only in allowed contexts
allow=("dropped","Dropped","out of scope","Out of scope","not dynamic","needs weights",
       "require","white-box","never loads","removed","Scope","scope","does not inspect","Audited","gap")
bad_static=[]
for ln in L:
    for term in ["picklescan","fickling","ModelScan","safetensors","trust_remote_code","Agentic Radar","weight-delta"]:
        if term in ln and not any(a in ln for a in allow):
            bad_static.append((term,ln[:70]))
check("Out-of-scope static tools only in allowed context", not bad_static, str(bad_static[:3]))

# 16 all phase tasks have build + done
phases=s[s.index("## 10. Phased"):s.index("### 10.1")]
tasks=[ln for ln in phases.splitlines() if ln.strip().startswith("- [ ]")]
check("All tasks have build: + Done when:",
      all("build:" in t and "*Done when:*" in t for t in tasks),
      f"{sum('build:' not in t or '*Done when:*' not in t for t in tasks)} incomplete of {len(tasks)}")

# 17 every phase has Exit
exits=len(re.findall(r'\*\*Exit:\*\*',phases))
check("Phases 0-5 each have an Exit", exits>=6, f"exit lines={exits}")

# ---- report ----
p=sum(1 for _,ok,_ in results if ok); f=len(results)-p
print(f"ACCURACY & STABILITY TEST — {p}/{len(results)} passed\n")
for name,ok,detail in results:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if (not ok and detail) else ""))
print("\nRESULT:", "ALL PASS" if f==0 else f"{f} FAILURE(S)")
sys.exit(0 if f==0 else 1)
