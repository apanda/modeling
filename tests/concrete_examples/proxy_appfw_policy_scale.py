import components
def L7FirewallProxyScalablePolicy (sz):
    assert(sz >= 1)
    ctx_components = ['a', 'c', 'p', 'f'] 
    ctx_components.extend(['e%d'%(e) for e in xrange(sz)])
    ctx_addresses = ['ip_%s'%(n) for n in ctx_components]
    ctx = components.Context(ctx_components, \
                            ctx_addresses)
    """
    I fucked up the naming this topology so it actually looks like
       A
        \
         P----F--C
        /
       E0 .. E1
    """
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx)
    #b = components.EndHost(ctx.b, net, ctx)
    c = components.EndHost(ctx.c, net, ctx)
    f = components.HTTPFirewall(ctx.f, net, ctx)
    p = components.AclWebProxy(ctx.p, net, ctx)
    net.SetIsolationConstraint (a, [p])
    #net.SetIsolationConstraint (b, [p, a])
    net.SetIsolationConstraint (c, [f])
    net.SetIsolationConstraint (f, [p, c])
    #net.SetIsolationConstraint (p, [a, b, f])
    f.AddAcls([(ctx.ip_a, ctx.ip_c), (ctx.ip_c, ctx.ip_a)])
    net.setAddressMappings([(a, ctx.ip_a), \
                            #(b, ctx.ip_b), \
                            (c, ctx.ip_c), \
                            (p, ctx.ip_p), \
                            (f, ctx.ip_f)])
    net.RoutingTable(a, [(ctx.ip_a, a), \
                         (ctx.ip_c, p), \
                         (ctx.ip_p, p)])

    #net.RoutingTable(b, [(ctx.ip_a, a), \
                         #(ctx.ip_b, b), \
                         #(ctx.ip_c, p), \
                         #(ctx.ip_p, p)])

    net.RoutingTable(f, [(ctx.ip_a, p), \
                         (ctx.ip_c, c), \
                         (ctx.ip_p, p)])

    net.RoutingTable(c, [(ctx.ip_a, f), \
                         (ctx.ip_c, c), \
                         (ctx.ip_p, f)])

    net.RoutingTable(p, [(ctx.ip_a, a), \
                         (ctx.ip_c, f), \
                         (ctx.ip_p, p)])

    net.Attach(a, c, p, f)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, c, p, f):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.c = c
            self.f = f
            self.p = p
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, c, p, f)
