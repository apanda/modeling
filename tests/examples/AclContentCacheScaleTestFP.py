import components
def AclContentCacheScaleTestFP (endhosts):
    """ACL content cache test"""
    nodes = ['cc', 'f', 's0', 's1']
    nodes.extend(['n_%d'%(i) for i in xrange(1, 3)])
    addresses = ['ip_%s'%(n) for n in nodes]
    other_addresses = ['ip_n_%d'%(d) for d in xrange(3, endhosts + 1)]
    act_addresses = list(addresses)
    act_addresses.extend(other_addresses)
    ctx = components.Context(nodes, act_addresses)
    net = components.Network (ctx)
    hosts = []
    for e in ['n_%d'%(i) for i in xrange(1, 3)]:
      hosts.append(components.EndHost(getattr(ctx, e), net, ctx))
    s0 = components.EndHost(ctx.s0, net, ctx)
    s1 = components.EndHost(ctx.s1, net, ctx)
    cc = components.AclContentCache(ctx.cc, net, ctx)
    f = components.AclFirewall(ctx.f, net, ctx)
    net.setAddressMappings([(getattr(ctx, n), getattr(ctx, 'ip_%s'%(n))) for n in nodes])
    addresses = [getattr(ctx, addr) for addr in addresses]
    for host in hosts:
        net.RoutingTable(host, [(x, f) for x in addresses])
    net.RoutingTable(f, [(x, cc) for x in addresses])
    net.RoutingTable(cc, [( getattr(ctx, 'ip_%s'%(n)), getattr(ctx, n)) for n in nodes])
    net.RoutingTable(s0, [(x, cc) for x in addresses])
    net.RoutingTable(s1, [(x, cc) for x in addresses])
    rnodes = list(hosts)
    rnodes.append(f)
    rnodes.append(cc)
    rnodes.append(s0)
    rnodes.append(s1)
    cc.AddAcls([(ctx.ip_s1, getattr(ctx, 'ip_n_%d'%i)) for i in xrange(2, endhosts + 1)])
    f.AddAcls([(ctx.ip_s1, getattr(ctx, 'ip_n_%d'%i)) for i in xrange(2, endhosts + 1)])
    net.Attach(*rnodes)
    class AclContentCacheReturn (object):
        def __init__ (self, net, ctx, cc, f, endhosts):
            self.net = net
            self.ctx = ctx
            self.cc = cc
            self.f = f
            self.s0 = s0
            self.s1 = s1
            self.endhosts = endhosts
            self.check = components.PropertyChecker (ctx, net)
    return AclContentCacheReturn(net, ctx, cc, f, hosts) 
