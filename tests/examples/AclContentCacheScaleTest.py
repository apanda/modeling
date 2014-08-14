import components
def AclContentCacheScaleTest (endhosts):
    """ACL content cache test"""
    nodes = ['cc', 'f']
    nodes.extend(['n_%d'%(i) for i in xrange(1, endhosts + 1)])
    addresses = ['ip_%s'%(n) for n in nodes]
    ctx = components.Context(nodes, addresses)
    net = components.Network (ctx)
    hosts = []
    for e in ['n_%d'%(i) for i in xrange(1, endhosts + 1)]:
      hosts.append(components.EndHost(getattr(ctx, e), net, ctx))
    cc = components.AclContentCache(ctx.cc, net, ctx)
    f = components.AclFirewall(ctx.f, net, ctx)
    net.setAddressMappings([(getattr(ctx, n), getattr(ctx, 'ip_%s'%(n))) for n in nodes])
    addresses = [getattr(ctx, addr) for addr in addresses]
    for host in hosts:
        net.RoutingTable(host, [(x, f) for x in addresses])
    net.RoutingTable(f, [(x, cc) for x in addresses])
    net.RoutingTable(cc, [( getattr(ctx, 'ip_%s'%(n)), getattr(ctx, n)) for n in nodes])
    rnodes = list(hosts)
    rnodes.append(f)
    rnodes.append(cc)
    f.AddAcls([(getattr(ctx, 'ip_n_%d'%(i)), getattr(ctx, 'ip_n_%d'%((i % (endhosts)) + 1))) for i in xrange(1,
        endhosts + 1)])
    cc.AddAcls([(getattr(ctx, 'ip_n_%d'%(i)), getattr(ctx, 'ip_n_%d'%((i % (endhosts)) + 1))) for i in xrange(1,
        endhosts + 1)])
    net.Attach(*rnodes)
    class AclContentCacheReturn (object):
        def __init__ (self, net, ctx, cc, f, endhosts):
            self.net = net
            self.ctx = ctx
            self.cc = cc
            self.f = f
            self.endhosts = endhosts
            self.check = components.PropertyChecker (ctx, net)
    return AclContentCacheReturn(net, ctx, cc, f, hosts) 
