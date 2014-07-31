import components
def AclContentCacheTest ():
    """ACL content cache test"""
    ctx = components.Context (['a', 'b', 'c', 'd', 'cc', 'f'],\
                              ['ip_a', 'ip_b', 'ip_c', 'ip_d', 'ip_cc', 'ip_f'])
    net = components.Network (ctx)
    a = components.EndHost(ctx.a, net, ctx) 
    b = components.EndHost(ctx.b, net, ctx) 
    c = components.EndHost(ctx.c, net, ctx) 
    d = components.EndHost(ctx.d, net, ctx) 
    cc = components.AclContentCache(ctx.cc, net, ctx)
    f = components.AclFirewall(ctx.f, net, ctx)
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (c, ctx.ip_c), \
                            (d, ctx.ip_d), \
                            (f, ctx.ip_f), \
                            (cc, ctx.ip_cc)])
    addresses = [ctx.ip_a, ctx.ip_b, ctx.ip_c, ctx.ip_d, ctx.ip_cc, ctx.ip_f]
    net.RoutingTable(a, [(x, f) for x in addresses])
    net.RoutingTable(b, [(x, f) for x in addresses])
    net.RoutingTable(c, [(x, f) for x in addresses])
    net.RoutingTable(d, [(x, f) for x in addresses])

    net.RoutingTable(cc, [(ctx.ip_a, a), \
                          (ctx.ip_b, b), \
                          (ctx.ip_c, c), \
                          (ctx.ip_d, d)])
    net.Attach(a, b, c, d, cc)
    endhosts = [a, b, c, d]
    f.AddAcls([(ctx.ip_a, ctx.ip_b), (ctx.ip_c, ctx.ip_d)])
    cc.AddAcls([(ctx.ip_a, ctx.ip_b), (ctx.ip_c, ctx.ip_d)])
    net.Attach(a, b, c, d, cc, f)
    endhosts = [a, b, c, d]
    class AclContentCacheReturn (object):
        def __init__ (self, net, ctx, a, b, c, d, cc, f):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.c = c
            self.d = d
            self.cc = cc
            self.f = f
            self.check = components.PropertyChecker (ctx, net)
    return AclContentCacheReturn(net, ctx, a, b, c, d, cc, f) 
