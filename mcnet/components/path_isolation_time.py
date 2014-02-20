import z3
import time
"""
Check if a property can be verified in a path independent manner (and verify it).
"""
VERIFIED_ISOLATION = 1
VERIFIED_GLOBAL = 2
UNKNOWN = 3

def CheckIsPathIndependentIsolatedTime (checker_path, condition, path_elements):
    """Check isolation based on path independence. This is modified so that when things are not isolated it does not
    try to compute the actual result once it knows."""
    class PathIndependenceResult (object):
        def __init__ (self, judgement, overapprox_result, underapprox_result = None):
            self.overapprox_result = overapprox_result
            self.underapprox_result = underapprox_result
            self.judgement = judgement
            self.ctx = overapprox_result.ctx

    print "%s Running overapproximate check"%(str(time.time()))
    result = checker_path.CheckConstraintsCompat (condition)
    print "%s Finished overapproximate check"%(str(time.time()))

    if result.result == z3.unsat:
        # If we are being conservative then this is sufficient; but it
        # probably is not.
        return PathIndependenceResult(VERIFIED_ISOLATION, result)

    if result.result == z3.unknown:
        # Hmm let us see what comes of the big thing.
        # We really do not know what in the world happened. So really it is possible that it was all path independent
        # and such but really things didn't work out
        return PathIndependenceResult(UNKNOWN, result)

    # This gives us the list of all participants. The reason for the :-1 is to get rid of the else_value which by
    # definition is 0
    participants = map(lambda l: l[0], result.model[result.model[result.ctx.etime].else_value().decl()].as_list()[:-1])
    z3PathElements = map(lambda n: n.z3Node, path_elements)
    bad_participants = filter(lambda p: not any(map(lambda z: p is z, z3PathElements)), participants)

    if len(bad_participants) == 0:
        return PathIndependenceResult(VERIFIED_ISOLATION, result)

    # OK so now we know that there are bad participants. In the normal way of the world we could just try globally but
    # we want to see if this really is path independent or not. Plus checking globally can be super expensive, so let
    # us attempt to not do that.
    p = z3.Const('path_independent_packet', result.ctx.packet)
    #elements_to_consider = filter(lambda p: not any(map(lambda z: p is z, z3PathElements)), map(lambda l: l.z3Node, \
            #result.ctx.node_list))
    #constraint = z3.And(map(lambda n: z3.ForAll([p], result.ctx.etime(n, p, result.ctx.send_event) == 0), \
                        #elements_to_consider))
    n = z3.Const('path_independent_node', result.ctx.node)
    constraint = z3.ForAll([n, p], z3.Implies(result.ctx.etime(n, p, result.ctx.send_event) > 0, \
                                    z3.Or(map(lambda x: n == x, z3PathElements))))
    checker_path.AddExternalConstraints(constraint)
    print "%s Running under-approximate check"%(str(time.time()))
    result2 = checker_path.CheckConstraintsCompat(condition)
    print "%s Done running under-approximate check"%(str(time.time()))
    checker_path.ClearExternalConstraints ()
    if result2.result != result.result:
        # Definitely not path independent.
        return PathIndependenceResult (VERIFIED_GLOBAL, result, result2)
    else:
        return PathIndependenceResult (VERIFIED_ISOLATION, result, result2)
