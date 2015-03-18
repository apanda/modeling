import sys
import itertools
if len(sys.argv) < 3:
    print >>sys.stderr, "Usages: %s file1 file2 ..."%(sys.argv[0])
files = []
for f in sys.argv[1:]:
    f = open(f)
    l = f.readlines()
    files.append(l)

for strings in itertools.izip_longest(*files):
    ident = None
    parts = []
    for string in strings:
        if string != None:
            sparts = string.strip().split()
            assert ident == None or ident == ' '.join(sparts[0:2])
            ident = ' '.join(sparts[0:2])
            parts.extend(sparts[2:-1])
    print "%s %s good"%(ident, ' '.join(parts))
