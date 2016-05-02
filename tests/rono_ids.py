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
    times = []
    
    # for (pubI, peerI, i) in zip(cycle(xrange(internal)),\
            # cycle(xrange(external)), range(samples)):
    pubI = 0
    peerI = 0
    i = 0
    ResetZ3(seed)
    topo = PolicyIDSShuntTopo (internal, internal, internal, external, 1)
    pub = topo.pub[pubI]
    peer = topo.peers[peerI]
    topo.net.Attach(pub, peer, topo.ids[peerI], topo.fws[peerI], topo.shunts[0])
    start = time.time()
    result = topo.checker.CheckIsolationProperty(peer, pub)
    stop = time.time()
    times.append(stop - start)
    assert(result.result == z3.sat)

    pub = 0
    peer = 0
    i = 0
    ResetZ3(seed)
    topo = PolicyIDSShuntTopo (internal, internal, internal, external, 1)
    pub = topo.priv[pubI]
    peer = topo.peers[peerI]
    topo.net.Attach(pub, peer, topo.ids[peerI], topo.fws[peerI], topo.shunts[0])
    start = time.time()
    result = topo.checker.CheckIsolationProperty(peer, pub)
    stop = time.time()
    times.append(stop - start)
    assert(result.result == z3.sat)

    ResetZ3(seed)
    topo = PolicyIDSShuntTopo (internal, internal, internal, external, 1)
    pub = topo.quarantine[pubI]
    peer = topo.peers[peerI]
    topo.net.Attach(pub, peer, topo.ids[peerI], topo.fws[peerI], topo.shunts[0])
    start = time.time()
    result = topo.checker.CheckIsolationProperty(peer, pub)
    stop = time.time()
    times.append(stop - start)
    assert(result.result == z3.sat)
    return times

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'RONO fat-tree test')
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
    for it in xrange(iters):
        for i in xrange(int_min, int_max):
            for e in xrange(ext_min, ext_max):
                times = Rono(2, 1, seed, samples)
                times = ' '.join(map(str, times))
                print it, i*3, e, times
