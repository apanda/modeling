from examples import PolicyIDSShuntTopo 
import z3
import time
import random
import sys
import argparse
from itertools import cycle

def ResetZ3 (seed):
    z3._main_ctx = None
    z3.main_ctx()
    z3.set_param('smt.random_seed', seed)

def Rono(internal, external, seed, samples):
    total_checks = 0
    total_time = 0.0
    times = []
    for (pubI, peerI, i) in zip(cycle(xrange(internal)),\
            cycle(xrange(external)), range(samples)):
      ResetZ3(seed)
      topo = PolicyIDSShuntTopo (internal, internal, internal, external, 1)
      pub = topo.pub[pubI]
      peer = topo.peers[peerI]
      topo.net.Attach(pub, peer, topo.ids[peerI], topo.fws[peerI], topo.shunts[0])
      start = time.time()
      result = topo.checker.CheckIsolationProperty(peer, pub)
      stop = time.time()
      total_checks += 1
      times.append(stop - start)
      total_time += (stop - start)
      assert(result.result == z3.sat)
    for (pub, peer, i) in zip(cycle(xrange(internal)),\
            cycle(xrange(external)), range(samples)):
      ResetZ3(seed)
      topo = PolicyIDSShuntTopo (internal, internal, internal, external, 1)
      pub = topo.priv[pubI]
      peer = topo.peers[peerI]
      topo.net.Attach(pub, peer, topo.ids[peerI], topo.fws[peerI], topo.shunts[0])
      start = time.time()
      result = topo.checker.CheckIsolationProperty(peer, pub)
      stop = time.time()
      total_checks += 1
      times.append(stop - start)
      total_time += (stop - start)
      assert(result.result == z3.sat)
    for (pub, peer, i) in zip(cycle(xrange(internal)),\
            cycle(xrange(external)), range(samples)):
      ResetZ3(seed)
      topo = PolicyIDSShuntTopo (internal, internal, internal, external, 1)
      pub = topo.quarantine[pubI]
      peer = topo.peers[peerI]
      topo.net.Attach(pub, peer, topo.ids[peerI], topo.fws[peerI], topo.shunts[0])
      start = time.time()
      result = topo.checker.CheckIsolationProperty(peer, pub)
      stop = time.time()
      total_checks += 1
      times.append(stop - start)
      total_time += (stop - start)
      assert(result.result == z3.sat)
    return (total_time / float(total_checks), times)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'Non-rono fat-tree test')
    parser.add_argument('--iters', type=int, nargs='?', default=10)
    parser.add_argument('--imin', type=int, nargs='?', default=1)
    parser.add_argument('--imax', type=int, nargs='?', default=10)
    parser.add_argument('--emin', type=int, nargs='?', default=1)
    parser.add_argument('--emax', type=int, nargs='?', default=10)
    parser.add_argument('--seed', type=int, nargs='?', default=42)
    parser.add_argument('--samples', type=int, nargs='?', default=5)
    args = parser.parse_args()
    iters = args.iters
    int_min = args.imin
    ext_min = args.emin
    int_max = args.imax
    ext_max = args.emax
    seed = args.seed
    samples = args.samples
    print "internal external time"
    for iter in xrange(iters):
        for i in xrange(int_min, int_max):
            for e in xrange(ext_min, ext_max):
                (t, times) = Rono(i, e, seed, samples)
                times = ' '.join(map(str, times))
                print "%d %d %f %s"%(i * 3, e, t, times)
