import components
def TrivialProxy ():
    ctx = components.Context(['a', 'b', 'p'], \
                            ['ip_a', 'ip_b', 'ip_p'])
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx)
    b = components.EndHost(ctx.b, net, ctx)
    p = components.WebProxy(ctx.p, net, ctx)
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (p, ctx.ip_p)])
    net.RoutingTable(a, [(ctx.ip_a, a), \
                         (ctx.ip_b, p)])
    net.RoutingTable(b, [(ctx.ip_a, p), \
                         (ctx.ip_b, b)])
    net.RoutingTable(p, [(ctx.ip_a, a), \
                         (ctx.ip_b, b)])
    net.Attach(a, b, p)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, b, p):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.p = p
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, b, p)
