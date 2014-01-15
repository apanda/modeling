import components

def LSRRFwTriv ():
    ctx = components.Context(['e0' , 'e1', 'a', 'b', 'f'], \
                            ['ip_e0', 'ip_e1', 'ip_a', 'ip_b','ip_f'])
    net = components.Network(ctx)
    # Register something that tells us about LSR
    ip_lsr_field = components.LSRROption ('ip_lsr', ctx)
    ctx.AddPolicy (ip_lsr_field)
    e0 = components.EndHost(ctx.e0, net, ctx)
    e1 = components.EndHost(ctx.e1, net, ctx)
    # Yeah I can put this in a list etc., doing it this way mostly for no good reason.
    a = components.LSRRRouter (ctx.a, ip_lsr_field, net, ctx)
    b = components.LSRRRouter (ctx.b, ip_lsr_field, net, ctx)
    f = components.AclFirewall (ctx.f, net, ctx)
    net.setAddressMappings([(e0, ctx.ip_e0), \
                            (e1, ctx.ip_e1), \
                            (a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (f, ctx.ip_f)])
    net.SetGateway(e0, a)
    net.SetGateway(e1, b)
    net.RoutingTable(a, [(ctx.ip_e0, e0), \
                            (ctx.ip_f, f), \
                            (ctx.ip_b, f), \
                            (ctx.ip_e1, f)])
    net.RoutingTable(b, [(ctx.ip_e0, f), \
                            (ctx.ip_f, f), \
                            (ctx.ip_b, f), \
                            (ctx.ip_e1, e1)])
    net.RoutingTable(f, [(ctx.ip_e0, a), \
                            (ctx.ip_e1, b), \
                            (ctx.ip_b, b), \
                            (ctx.ip_a, a)])
    node_dict = {'e0': e0, \
                 'e1': e1, \
                 'a': a, \
                 'b': b, \
                 'f': f}
    net.Attach(*node_dict.values())
    class LSRRReturn (object):
        def __init__ (self, net, ctx, **nodes):
            self.net = net
            self.ctx = ctx
            for k, v in nodes.iteritems():
                setattr(self, k, v)
            self.check = components.PropertyChecker (ctx, net)
    return LSRRReturn (net, ctx, **node_dict)
