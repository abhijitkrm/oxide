import sys,collections
folded=collections.Counter(); stack=[]; comm=None
for line in sys.stdin:
    line=line.rstrip("\n")
    if not line.strip():
        if stack and comm: folded[comm+";"+";".join(reversed(stack))]+=1
        stack=[]; comm=None; continue
    if not line.startswith((" ","\t")):
        parts=line.split(); comm=parts[0] if parts else "?"; stack=[]; continue
    p=line.split(None,1); stack.append((p[1] if len(p)>1 else p[0]).replace(";","_"))
for k,v in folded.most_common(6000): print(k,v)
