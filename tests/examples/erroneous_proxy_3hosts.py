import components
def ErroneousProxyMultiple ():
    ctx = components.Context(['a', 'b', 'c', 'p'], \
                            ['ip_a', 'ip_b', 'ip_c', 'ip_p'])
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx)
    b = components.EndHost(ctx.b, net, ctx)
    c = components.EndHost(ctx.c, net, ctx)
    p = components.ErroneousAclWebProxy(ctx.p, net, ctx)
    p.AddAcls([(ctx.ip_a, ctx.ip_b), (ctx.ip_b, ctx.ip_a)])
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (c, ctx.ip_c), \
                            (p, ctx.ip_p)])
    net.RoutingTable(a, [(ctx.ip_a, a), \
                         (ctx.ip_b, p), \
                         (ctx.ip_c, p), \
                         (ctx.ip_p, p)])

    net.RoutingTable(b, [(ctx.ip_a, p), \
                         (ctx.ip_b, b), \
                         (ctx.ip_c, p), \
                         (ctx.ip_p, p)])

    net.RoutingTable(c, [(ctx.ip_a, p), \
                         (ctx.ip_b, p), \
                         (ctx.ip_c, c), \
                         (ctx.ip_p, p)])

    net.RoutingTable(p, [(ctx.ip_a, a), \
                         (ctx.ip_b, b), \
                         (ctx.ip_c, c), \
                         (ctx.ip_p, p)])
    net.Attach(a, b, c, p)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, b, c, p):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.c = c
            self.p = p
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, b, c, p)
