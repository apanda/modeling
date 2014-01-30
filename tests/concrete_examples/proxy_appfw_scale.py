import components
def L7FirewallProxyScale (sz):
    assert(sz >= 1)
    ctx_components = ['a', 's', 'p', 'f'] 
    other_endhosts = ['e%d'%(e) for e in xrange(sz)]
    ctx_components.extend(other_endhosts)
    ctx_addresses = ['ip_%s'%(n) for n in ctx_components]
    ctx = components.Context(ctx_components, \
                            ctx_addresses)
    """
    I fucked up the naming this topology so it actually looks like
       A
        \
         F----P--S
        /
       E0 .. E1

       NOTE NOTE NOTE
       In this case F is a proxy, P is a firewall because you know why the hell not
    """

    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx)
    s = components.EndHost(ctx.s, net, ctx)
    f = components.WebProxy(ctx.f, net, ctx)
    p = components.HTTPFirewall(ctx.p, net, ctx)
    other_endhosts = [components.EndHost(getattr(ctx, 'e%d'%(e)), net, ctx) for e in xrange(sz)] 

    net.SetIsolationConstraint (a, [f])
    net.SetIsolationConstraint (s, [p])
    net.SetIsolationConstraint (p, [s, f])
    p.AddAcls([(ctx.ip_a, ctx.ip_s), (ctx.ip_s, ctx.ip_a)])

    address_mappings = zip(map(lambda n: getattr(ctx, n), ctx_components), map(lambda a: getattr(ctx, a), ctx_addresses))

    net.setAddressMappings(address_mappings)
    host_routing = [(ctx.ip_s, f), \
                    (ctx.ip_p, f)]

    net.RoutingTable(a, host_routing)

    for n in other_endhosts:
        net.RoutingTable(n, host_routing)

    firewall_routing = [(ctx.ip_a, a), \
                        (ctx.ip_p, p), \
                        (ctx.ip_s, p)]
    firewall_routing.extend([(getattr(ctx, 'ip_%s'%(n.z3Node)), n) for n in other_endhosts])

    net.RoutingTable(f, firewall_routing)

    nodes = [a, s, p, f]
    nodes.extend(other_endhosts)

    net.Attach(*nodes)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, s, p, f, others):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.s = s
            self.f = f
            self.p = p
            self.others = others
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, s, p, f, other_endhosts)
