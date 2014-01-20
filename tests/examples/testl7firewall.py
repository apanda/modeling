import components
def L7FirewallSimple ():
    ctx = components.Context(['a', 'b', 'c', 'f'], \
                            ['ip_a', 'ip_b', 'ip_c', 'ip_f'])
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx)
    b = components.EndHost(ctx.b, net, ctx)
    c = components.EndHost(ctx.c, net, ctx)
    f = components.HTTPFirewall(ctx.f, net, ctx)
    net.SetIsolationConstraint (a, [f])
    net.SetIsolationConstraint (b, [f])
    net.SetIsolationConstraint (c, [f])
    f.AddAcls([(ctx.ip_a, ctx.ip_c), (ctx.ip_c, ctx.ip_a)])
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (c, ctx.ip_c), \
                            (f, ctx.ip_f)])
    net.RoutingTable(a, [(ctx.ip_a, a), \
                         (ctx.ip_b, f), \
                         (ctx.ip_c, f)])

    net.RoutingTable(b, [(ctx.ip_a, f), \
                         (ctx.ip_b, b), \
                         (ctx.ip_c, f)])

    net.RoutingTable(f, [(ctx.ip_a, a), \
                         (ctx.ip_b, b), \
                         (ctx.ip_c, c)])

    net.RoutingTable(c, [(ctx.ip_a, f), \
                         (ctx.ip_b, f), \
                         (ctx.ip_c, c)])

    net.Attach(a, b, c, f)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, b, c, f):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.c = c
            self.f = f
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, b, c, f)
