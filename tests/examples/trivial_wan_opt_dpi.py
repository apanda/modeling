import components
def TrivialWanOptimizerAndDPI ():
    ctx = components.Context(['a', 'b', 'w0', 'w1', 'd'], \
                            ['ip_a', 'ip_b', 'ip_w0', 'ip_w1', 'ip_d'])
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx)
    b = components.EndHost(ctx.b, net, ctx)
    gzip = components.CompressionAlgorithm('gzip')
    inspect = components.DPIPolicy ('PRISM')
    ctx.AddPolicy (gzip)
    ctx.AddPolicy (inspect)
    w0 = components.WanOptimizer(gzip.compress, ctx.w0, net, ctx)
    w1 = components.WanOptimizer(gzip.decompress, ctx.w1, net, ctx)
    d = components.IPS(inspect, ctx.d, net, ctx)
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (w0, ctx.ip_w0), \
                            (w1, ctx.ip_w1), \
                            (d, ctx.ip_d)])
    net.RoutingTable(a, [(ctx.ip_a, a), \
                         (ctx.ip_b, w0)])
    net.RoutingTable(b, [(ctx.ip_a, w0), \
                         (ctx.ip_b, b)])
    net.RoutingTable(w0, [(ctx.ip_a, d), \
                         (ctx.ip_b, d)])
    net.RoutingTable(d, [(ctx.ip_a, w1), \
                         (ctx.ip_b, w1)])
    net.RoutingTable(w1, [(ctx.ip_a, a), \
                         (ctx.ip_b, b)])
    net.Attach(a, b, w0, w1, d)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, b, w0, w1, d, dpi_policy):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.d = d
            self.dpi_policy = dpi_policy
            self.w0 = w0
            self.w1 = w1
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, b, w0, w1, d, inspect)
