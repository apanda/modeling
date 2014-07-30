import components
def ContentCacheTest ():
    """Learning firewall test"""
    ctx = components.Context (['a', 'b', 'c', 'd', 'cc'],\
                              ['ip_a', 'ip_b', 'ip_c', 'ip_d', 'ip_cc'])
    net = components.Network (ctx)
    a = components.EndHost(ctx.a, net, ctx) 
    b = components.EndHost(ctx.b, net, ctx) 
    c = components.EndHost(ctx.c, net, ctx) 
    d = components.EndHost(ctx.d, net, ctx) 
    cc = components.ContentCache(ctx.cc, net, ctx)
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (c, ctx.ip_c), \
                            (d, ctx.ip_d), \
                            (cc, ctx.ip_cc)])
    addresses = [ctx.ip_a, ctx.ip_b, ctx.ip_c, ctx.ip_d, ctx.ip_cc]
    net.RoutingTable(a, [(x, cc) for x in addresses])
    net.RoutingTable(b, [(x, cc) for x in addresses])
    net.RoutingTable(c, [(x, cc) for x in addresses])
    net.RoutingTable(d, [(x, cc) for x in addresses])

    net.RoutingTable(cc, [(ctx.ip_a, a), \
                          (ctx.ip_b, b), \
                          (ctx.ip_c, c), \
                          (ctx.ip_d, d)])
    net.Attach(a, b, c, d, cc)
    endhosts = [a, b, c, d]
    #cc.AddAcls([(ctx.ip_a, ctx.ip_b), (ctx.ip_c, ctx.ip_d)])
    net.Attach(a, b, c, d, cc)
    endhosts = [a, b, c, d]
    class LearnFwReturn (object):
        def __init__ (self, net, ctx, a, b, c, d, cc):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.c = c
            self.d = d
            self.cc = cc
            self.check = components.PropertyChecker (ctx, net)
    return LearnFwReturn(net, ctx, a, b, c, d, cc) 
