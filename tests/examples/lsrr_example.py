import components

def LSRRExample ():
    ctx = components.Context(['e0' , 'e1', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'], \
                            ['ip_e0', 'ip_e1', 'ip_a', 'ip_b', 'ip_c', 'ip_d', 'ip_e', 'ip_f', 'ip_g', 'ip_h'])
    net = components.Network(ctx)
    # Register something that tells us about LSR
    ip_lsr_field = components.LSRROption ('ip_lsr', ctx)
    ctx.AddPolicy (ip_lsr_field)
    e0 = components.EndHost(ctx.e0, net, ctx)
    e1 = components.EndHost(ctx.e1, net, ctx)
    # Yeah I can put this in a list etc., doing it this way mostly for no good reason.
    a = components.LSRRRouter (ctx.a, ip_lsr_field, net, ctx)
    b = components.LSRRRouter (ctx.b, ip_lsr_field, net, ctx)
    c = components.LSRRRouter (ctx.c, ip_lsr_field, net, ctx)
    d = components.LSRRRouter (ctx.d, ip_lsr_field, net, ctx)
    e = components.LSRRRouter (ctx.e, ip_lsr_field, net, ctx)
    f = components.LSRRRouter (ctx.f, ip_lsr_field, net, ctx)
    g = components.LSRRRouter (ctx.g, ip_lsr_field, net, ctx)
    h = components.LSRRRouter (ctx.h, ip_lsr_field, net, ctx)
    net.setAddressMappings([(e0, ctx.ip_e0), \
                            (e1, ctx.ip_e1), \
                            (a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (c, ctx.ip_c), \
                            (d, ctx.ip_d), \
                            (e, ctx.ip_e), \
                            (f, ctx.ip_f), \
                            (g, ctx.ip_g), \
                            (h, ctx.ip_h)])
    routing_table = [(ctx.ip_e0, e0), \
                     (ctx.ip_e1, e1), \
                     (ctx.ip_a, a), \
                     (ctx.ip_b, b), \
                     (ctx.ip_c, c), \
                     (ctx.ip_d, d), \
                     (ctx.ip_e, e), \
                     (ctx.ip_f, f), \
                     (ctx.ip_g, g), \
                     (ctx.ip_h, h)]
    nodes = [e0, e1, a, b, c, d, e, f, g, h]
    node_dict = {'a': a, \
                 'b': b, \
                 'c': c, \
                 'd': d, \
                 'e': e, \
                 'f': f, \
                 'g': g, \
                 'h': h}
    for n in nodes:
        net.RoutingTable(n, routing_table)
    net.Attach(*nodes)
    class LSRRReturn (object):
        def __init__ (self, net, ctx, e0, e1, **nodes):
            self.net = net
            self.ctx = ctx
            self.e0 = e0
            self.e1 = e1
            for k, v in nodes.iteritems():
                setattr(self, k, v)
            self.check = components.PropertyChecker (ctx, net)
    return LSRRReturn (net, ctx, e0, e1, **node_dict)
