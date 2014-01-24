import sys
if len(sys.argv) != 2:
    print >>sys.stderr, "Usage: %s file"%(sys.argv[0])
f = open(sys.argv[1])
for l in f:
    parts = l.split()[:-1]
    num = int(parts[0])
    obs = map(float, parts[1:])
    if len(obs) == 0:
        continue
    s = sum(obs)
    avg = s/float(len(obs))
    print "%s %f %f %d"%(num, avg, s, len(obs))
