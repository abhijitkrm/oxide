import sys,collections
key=sys.argv[1]; depth=int(sys.argv[2]) if len(sys.argv)>2 else 1
c=collections.Counter(); leaf=collections.defaultdict(collections.Counter); tot=0; stack=[]
def flush():
    global tot
    for i,f in enumerate(stack):
        if key in f:
            j=max(i-depth,0); callee=stack[j][:84]; c[callee]+=1; leaf[callee][stack[0][:66]]+=1; tot+=1; break
for line in sys.stdin:
    line=line.rstrip("\n")
    if not line.strip():
        if stack: flush()
        stack=[]; continue
    if not line.startswith((" ","\t")):
        stack=[]; continue
    p=line.split(None,1); stack.append(p[1] if len(p)>1 else p[0])
print("samples under",key,":",tot)
for f,n in c.most_common(14):
    print("%5.1f%%  %s"%(100*n/tot,f))
    for l,m in leaf[f].most_common(2): print("          leaf %3.0f%%  %s"%(100*m/n,l))
