import sys
if len(sys.argv) != 3:
    print >>sys.stderr, "Usages: %s file1 file2"%(sys.argv[0])
f0 = open(sys.argv[1])
f1 = open(sys.argv[2])
for (l0, l1) in zip(f0, f1):
    l0 = l0.strip().split()
    l1 = l1.strip().split()
    print "%s %s %s %s"%(l0[0], ' '.join(map(str, l0[1:-1])), ' '.join(map(str, l1[1:-1])), l1[-1])
