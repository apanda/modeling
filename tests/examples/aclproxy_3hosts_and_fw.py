import components
def AclProxyMultiFw ():
    """This is really just a version of ErroneousProxyMultiFw with AclFirewall. As shown by that function there really isn't a
    way to violate isolation here. Here by using something that is path independent we can prove things without really having to deal 
    with any of the other things"""
    ctx = components.Context(['a', 'b', 'c', 'p', 'f'], \
                            ['ip_a', 'ip_b', 'ip_c', 'ip_p', 'ip_f'])
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx)
    b = components.EndHost(ctx.b, net, ctx)
    c = components.EndHost(ctx.c, net, ctx)
    p = components.AclWebProxy(ctx.p, net, ctx)
    f = components.AclFirewall(ctx.f, net, ctx)
    net.SetIsolationConstraint (a, [p])
    net.SetIsolationConstraint (b, [p])
    net.SetIsolationConstraint (p, [a, b, f])
    p.AddAcls([(ctx.ip_a, ctx.ip_b), (ctx.ip_b, ctx.ip_a)])
    f.AddAcls([(ctx.ip_c, ctx.ip_a), (ctx.ip_a, ctx.ip_c)])
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (c, ctx.ip_c), \
                            (p, ctx.ip_p), \
                            (f, ctx.ip_f)])
    net.RoutingTable(a, [(ctx.ip_a, a), \
                         (ctx.ip_b, p), \
                         (ctx.ip_c, p), \
                         (ctx.ip_p, p)])

    net.RoutingTable(b, [(ctx.ip_a, p), \
                         (ctx.ip_b, b), \
                         (ctx.ip_c, p), \
                         (ctx.ip_p, p)])

    net.RoutingTable(f, [(ctx.ip_a, p), \
                         (ctx.ip_b, p), \
                         (ctx.ip_c, c), \
                         (ctx.ip_p, p)])

    net.RoutingTable(c, [(ctx.ip_a, f), \
                         (ctx.ip_b, f), \
                         (ctx.ip_c, c), \
                         (ctx.ip_p, f)])

    net.RoutingTable(p, [(ctx.ip_a, a), \
                         (ctx.ip_b, b), \
                         (ctx.ip_c, f), \
                         (ctx.ip_p, p)])
    net.Attach(a, b, c, p, f)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, b, c, p, f):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.c = c
            self.p = p
            self.f = f
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, b, c, p, f)
