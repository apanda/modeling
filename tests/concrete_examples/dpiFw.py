import components
def dpiFw ():
    """DPI Firewall. Everything is UNSAT since no bad packets make it through"""
    ctx = components.Context (['a', 'b', 'c', 'd', 'fw', 'w'],\
                              ['ip_a', 'ip_b', 'ip_c', 'ip_d', 'ip_f', 'ip_w'])

    dpi_policy = components.DPIPolicy('dpi')
    ctx.AddPolicy (dpi_policy)
    comp = components.CompressionAlgorithm ('gzip')
    ctx.AddPolicy(comp)

    net = components.Network (ctx)
    a = components.EndHost(ctx.a, net, ctx)
    b = components.EndHost(ctx.b, net, ctx)
    c = components.EndHost(ctx.c, net, ctx)
    d = components.EndHost(ctx.d, net, ctx)
    fw = components.IPS(dpi_policy, ctx.fw, net, ctx)
    w = components.WanOptimizer(comp.compress, ctx.w, net, ctx)
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (c, ctx.ip_c), \
                            (d, ctx.ip_d), \
                            (w, ctx.ip_w), \
                            (fw, ctx.ip_f)])
    addresses = [ctx.ip_a, ctx.ip_b, ctx.ip_c, ctx.ip_d, ctx.ip_f]
    net.RoutingTable(a, [(x, w) for x in addresses])
    net.RoutingTable(b, [(x, w) for x in addresses])
    net.RoutingTable(c, [(x, w) for x in addresses])
    net.RoutingTable(d, [(x, w) for x in addresses])
    net.RoutingTable(w,  [(ctx.ip_a, fw), \
                          (ctx.ip_b, fw), \
                          (ctx.ip_c, fw), \
                          (ctx.ip_d, fw)])

    net.RoutingTable(fw, [(ctx.ip_a, a), \
                          (ctx.ip_b, b), \
                          (ctx.ip_c, c), \
                          (ctx.ip_d, d)])
    nodes = {'a': a,
             'b': b,
             'c': c,
             'd': d,
             'w': w,
             'fw': fw}
    net.Attach(*nodes.values())
    class DPIReturn (object):
        def __init__ (self, net, ctx, dpi_policy, comp, **nodes):
            self.net = net
            self.ctx = ctx
            self.dpi_policy = dpi_policy
            self.comp = comp
            for k, v in nodes.iteritems():
                setattr(self, k, v)
            self.check = components.PropertyChecker (ctx, net)
    return DPIReturn (net, ctx, dpi_policy, comp, **nodes)


#return dict(ctx = ctx, net = net, endhosts = endhosts, policy = dpi_policy, check=check)
