from concrete_examples import SymmetryTest1, ReseedZ3
import sys
import time
import z3

def SymmetryTest(iters, min_size, max_size):
  times = []
  print "SymTest start"
  for sz in xrange(min_size, max_size):
    for it in xrange(iters):
      ReseedZ3()
      (sym, asym) = SymmetryTest1(sz) 
      start = time.time()
      ret = sym.check.CheckIsolationProperty(sym.a, sym.endhosts[0])
      assert ret.result == z3.unsat
      ret = sym.check.CheckIsolationProperty(sym.a, sym.endhosts[1])
      assert ret.result == z3.unsat
      stop = time.time()
      sym_time = stop - start
      ReseedZ3()
      start = time.time()
      ret = asym.check.CheckIsolationProperty(asym.a, asym.endhosts[0])
      assert ret.result == z3.unsat
      ret = asym.check.CheckIsolationProperty(asym.a, asym.endhosts[1])
      assert ret.result == z3.unsat
      stop = time.time()
      asym_time = stop - start
      print "%d %f %f"%(sz, sym_time, asym_time)
if __name__ == "__main__":
  if len(sys.argv) != 4:
    print >>sys.stderr, "Usage: %s iters min max"%(sys.argv[0])
    sys.exit(0)
  SymmetryTest(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
