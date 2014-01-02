import components
def TrivialWanOptimizerDeOptimizer ():
    ctx = components.Context(['a', 'b', 'w0', 'w1'], \
                            ['ip_a', 'ip_b', 'ip_w0', 'ip_w1'])
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx)
    b = components.EndHost(ctx.b, net, ctx)
    gzip = components.CompressionAlgorithm('gzip')
    ctx.AddPolicy (gzip)
    w0 = components.WanOptimizer(gzip.compress, ctx.w0, net, ctx)
    w1 = components.WanOptimizer(gzip.decompress, ctx.w1, net, ctx)
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (w0, ctx.ip_w0), \
                            (w1, ctx.ip_w1)])
    net.RoutingTable(a, [(ctx.ip_a, a), \
                         (ctx.ip_b, w0)])
    net.RoutingTable(b, [(ctx.ip_a, w0), \
                         (ctx.ip_b, b)])
    net.RoutingTable(w0, [(ctx.ip_a, w1), \
                         (ctx.ip_b, w1)])
    net.RoutingTable(w1, [(ctx.ip_a, a), \
                         (ctx.ip_b, b)])
    net.Attach(a, b, w0, w1)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, b, w0, w1):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.w0 = w0
            self.w1 = w1
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, b, w0, w1)
