import components
def AclContentCacheSimpleTest ():
    """ACL content cache test"""
    ctx = components.Context (['a', 'b', 'cc'],\
                              ['ip_a', 'ip_b', 'ip_cc'])
    net = components.Network (ctx)
    a = components.EndHost(ctx.a, net, ctx) 
    b = components.EndHost(ctx.b, net, ctx) 
    cc = components.AclContentCache(ctx.cc, net, ctx)
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (cc, ctx.ip_cc)])
    addresses = [ctx.ip_a, ctx.ip_b, ctx.ip_cc]
    net.RoutingTable(a, [(x, cc) for x in addresses])
    net.RoutingTable(b, [(x, cc) for x in addresses])

    net.RoutingTable(cc, [(ctx.ip_a, a), \
                          (ctx.ip_b, b)])
    endhosts = [a, b]
    cc.AddAcls([(ctx.ip_a, ctx.ip_b)])
    endhosts = [a, b]
    net.Attach(a, b, cc)
    class AclContentCacheSimpleReturn (object):
        def __init__ (self, net, ctx, a, b, cc):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.cc = cc
            self.check = components.PropertyChecker (ctx, net)
    return AclContentCacheSimpleReturn(net, ctx, a, b, cc) 

# To run in a Python shell
# from examples import AclContentCacheSimpleTest
# m = AclContentCacheSimpleTest()
# For unsat result y = m.check.CheckDataIsolationProperty(m.a, m.b)
# For sat result y = m.check.CheckDataIsolationProperty(m.b, m.a)
