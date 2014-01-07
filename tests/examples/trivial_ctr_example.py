import components
def TrivialCtrExample ():
    ctx = components.Context(['a', 'b', 'c'], \
                            ['ip_a', 'ip_b', 'ip_c'])
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx)
    b = components.EndHost(ctx.b, net, ctx)
    c = components.NetworkCounter(ctx.c, net, ctx)

    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (c, ctx.ip_c)])
    net.RoutingTable(a, [(ctx.ip_a, a), \
                         (ctx.ip_b, c)])
    net.RoutingTable(b, [(ctx.ip_a, c), \
                         (ctx.ip_b, b)])
    net.RoutingTable(c, [(ctx.ip_a, a), \
                         (ctx.ip_b, b)])
    net.Attach(a, b, c)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, b, c):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.c = c
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, b, c)
