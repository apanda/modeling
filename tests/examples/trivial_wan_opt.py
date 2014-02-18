import components
def TrivialWanOptimizer ():
    ctx = components.Context(['a', 'b', 'w'], \
                            ['ip_a', 'ip_b', 'ip_w'])
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx)
    b = components.EndHost(ctx.b, net, ctx)
    gzip = components.CompressionAlgorithm('gzip')
    ctx.AddPolicy (gzip)
    w = components.WanOptimizer(gzip.compress, ctx.w, net, ctx)
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (w, ctx.ip_w)])
    net.RoutingTable(a, [(ctx.ip_a, a), \
                         (ctx.ip_b, w)])
    net.RoutingTable(b, [(ctx.ip_a, w), \
                         (ctx.ip_b, b)])
    net.RoutingTable(w, [(ctx.ip_a, a), \
                         (ctx.ip_b, b)])
    net.Attach(a, b, w)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, b, w):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.w = w
            self.gzip = gzip
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, b, w)
