import components
def TrivialLbalancer ():
    ctx = components.Context(['a', 'b', 'f', 'l'], \
                            ['ip_a', 'ip_b', 'ip_f', 'ip_l'])
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx)
    b = components.EndHost(ctx.b, net, ctx)
    f = components.AclFirewall(ctx.f, net, ctx)
    l = components.LoadBalancer(ctx.l, net, ctx)
    f.AddAcls([(ctx.ip_a, ctx.ip_b), (ctx.ip_b, ctx.ip_a)])

    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (f, ctx.ip_f), \
                            (l, ctx.ip_l)])
    net.RoutingTable(a, [(ctx.ip_a, a), \
                         (ctx.ip_b, l)])
    net.RoutingTable(b, [(ctx.ip_a, l), \
                         (ctx.ip_b, b)])
    net.RoutingTable(l, [(ctx.ip_a, [f, a]), \
                         (ctx.ip_b, [f, b])])
    net.RoutingTable(f, [(ctx.ip_a, a), \
                         (ctx.ip_b, b)])
    net.Attach(a, b, l, f)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, b, l, f):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.l = l
            self.f = f
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, b, l, f)
