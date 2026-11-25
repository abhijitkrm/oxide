import os,sys,time,json,collections,urllib.request
pid=int(sys.argv[1]); port=int(sys.argv[2]); secs=float(sys.argv[3])
NAMES={0:"read",1:"write",7:"poll",17:"pread64",20:"writev",45:"recvfrom",44:"sendto",202:"futex",230:"clock_nanosleep",232:"epoll_wait",270:"pselect6",271:"ppoll",281:"epoll_pwait",35:"nanosleep",74:"fsync",75:"fdatasync",23:"select",-1:"running"}
def height():
    try:
        b=json.dumps({"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}).encode()
        r=urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}",b,{"content-type":"application/json"}),timeout=1)
        return int(json.loads(r.read())["result"],16)
    except Exception: return None
rows=[]; t0=time.time(); lasth=None; lastchg=t0
while time.time()-t0<secs:
    h=height(); now=time.time()
    if h is not None and h!=lasth: lasth=h; lastchg=now
    stalled=(now-lastchg)>1.0
    snap=collections.Counter()
    try:
        for tid in os.listdir(f"/proc/{pid}/task"):
            try:
                comm=open(f"/proc/{pid}/task/{tid}/comm").read().strip()
                st=open(f"/proc/{pid}/task/{tid}/stat").read().rsplit(")",1)[1].split()[0]
                sc=open(f"/proc/{pid}/task/{tid}/syscall").read().split()[0]
                nm=NAMES.get(int(sc),sc) if sc!="running" else "running"
                snap[(comm,st,nm)]+=1
            except Exception: pass
    except Exception: break
    rows.append((stalled,snap)); time.sleep(0.05)
agg={True:collections.Counter(),False:collections.Counter()}
n={True:0,False:0}
for stalled,snap in rows:
    n[stalled]+=1
    for k,v in snap.items(): agg[stalled][k]+=v
print("samples: stalled=%d normal=%d"%(n[True],n[False]))
for flag,label in ((True,"DURING STALL"),(False,"NORMAL")):
    print("== "+label+" (avg threads per sample in each state; threads that are not idle workers)")
    for (comm,st,nm),v in agg[flag].most_common(40):
        if st=="S" and nm in ("futex","epoll_wait","epoll_pwait","poll","ppoll","clock_nanosleep","nanosleep","read","recvfrom") and comm.startswith(("rayon","oxide-devnet","p2p-","oxide-intake","tokio")) is False: pass
        print("  %-18s %s %-16s %.2f"%(comm,st,nm,v/max(n[flag],1)))
