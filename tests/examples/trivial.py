import components
def Trivial ():
    ctx = components.Context(['a', 'b'], \
                            ['ip_a', 'ip_b'])
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx) 
    b = components.EndHost(ctx.b, net, ctx) 
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b)])
    net.RoutingTable(a, [(ctx.ip_a, a), \
                         (ctx.ip_b, b)])
    net.RoutingTable(b, [(ctx.ip_a, a), \
                         (ctx.ip_b, b)])
    net.Attach(a, b)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, b):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, b)
