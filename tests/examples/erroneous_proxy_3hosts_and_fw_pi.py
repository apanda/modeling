import components
def ErroneousProxyMultiFwPi ():
    ctx = components.Context(['a', 'b', 'c', 'p', 'f'], \
                            ['ip_a', 'ip_b', 'ip_c', 'ip_p', 'ip_f'])
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx)
    b = components.EndHost(ctx.b, net, ctx)
    # c = components.EndHost(ctx.c, net, ctx)
    p = components.ErroneousAclWebProxy(ctx.p, net, ctx)
    # f = components.AclFirewall(ctx.f, net, ctx)
    p.AddAcls([(ctx.ip_a, ctx.ip_b), (ctx.ip_b, ctx.ip_a)])
    # f.AddAcls([(ctx.ip_c, ctx.ip_a), (ctx.ip_a, ctx.ip_c)])
    net.SetIsolationConstraint (a, [p])
    net.SetIsolationConstraint (b, [p])
    net.SetIsolationConstraint (p, [a, b, ctx.f])
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (ctx.c, ctx.ip_c), \
                            (p, ctx.ip_p), \
                            (ctx.f, ctx.ip_f)])
    net.RoutingTable(a, [(ctx.ip_a, a), \
                         (ctx.ip_b, p), \
                         (ctx.ip_c, p), \
                         (ctx.ip_p, p)])

    net.RoutingTable(b, [(ctx.ip_a, p), \
                         (ctx.ip_b, b), \
                         (ctx.ip_c, p), \
                         (ctx.ip_p, p)])

    net.RoutingTable(p, [(ctx.ip_a, a), \
                         (ctx.ip_b, b), \
                         #(ctx.ip_c, ctx.f), \
                         (ctx.ip_p, p)])
    net.Attach(a, b, p)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, b, c, p, f):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.c = c
            self.p = p
            self.f = f
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, b, ctx.c, p, ctx.f)
