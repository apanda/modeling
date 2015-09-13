import components
def AclContentCacheScaleTestFP (endhosts):
    """ACL content cache test"""
    nodes = ['cc', 'f', 's0']
    nodes.extend(['n_%d'%(i) for i in xrange(0, 2)])
    addresses = ['ip_%s'%(n) for n in nodes]
    addresses.append('ip_cc')
    addresses.append('ip_f')
    addresses.append('ip_s0')
    ctx = components.Context(nodes, addresses)
    net = components.Network (ctx)
    hosts = []
    for e in ['n_%d'%(i) for i in xrange(0, 2)]:
      hosts.append(components.EndHost(getattr(ctx, e), net, ctx))
    s0 = components.EndHost(ctx.s0, net, ctx)
    cc = components.AclContentCache(ctx.cc, net, ctx)
    f = components.AclFirewall(ctx.f, net, ctx)
    address_mappings = [(getattr(ctx, n), getattr(ctx, 'ip_%s'%(n))) for n in nodes]
    address_mappings.extend([(ctx.s0, ctx.ip_s0),
			     (ctx.cc, ctx.ip_cc),
			     (ctx.f, ctx.ip_f)])
    net.setAddressMappings(address_mappings)
    addresses = [getattr(ctx, addr) for addr in addresses]
    for host in hosts:
        net.RoutingTable(host, [(x, f) for x in addresses])
    net.RoutingTable(f, [(x, cc) for x in addresses])
    net.RoutingTable(cc, [( getattr(ctx, 'ip_%s'%(n)), getattr(ctx, n)) for n in nodes])
    net.RoutingTable(s0, [(x, cc) for x in addresses])
    rnodes = list(hosts)
    rnodes.append(f)
    rnodes.append(cc)
    rnodes.append(s0)

    acls = [(ctx.ip_s0, ctx.ip_n_0)]

    cc.AddAcls(acls)
    f.AddAcls(acls)
    net.Attach(*rnodes)
    class AclContentCacheReturn (object):
        def __init__ (self, net, ctx, cc, f, endhosts):
            self.net = net
            self.ctx = ctx
            self.cc = cc
            self.f = f
            self.s0 = s0
            self.endhosts = endhosts
            self.check = components.PropertyChecker (ctx, net)
    return AclContentCacheReturn(net, ctx, cc, f, hosts) 

def NAclContentCacheScaleTestFP (endhosts):
    """ACL content cache test"""
    nodes = ['cc', 'f', 's0']
    nodes.extend(['n_%d'%(i) for i in xrange(0, 2)])
    addresses = ['ip_%s'%(n) for n in nodes]
    addresses.append('ip_cc')
    addresses.append('ip_f')
    addresses.append('ip_s0')
    ctx = components.Context(nodes, addresses)
    net = components.Network (ctx)
    hosts = []
    for e in ['n_%d'%(i) for i in xrange(0, 2)]:
      hosts.append(components.EndHost(getattr(ctx, e), net, ctx))
    s0 = components.EndHost(ctx.s0, net, ctx)
    cc = components.AclContentCache(ctx.cc, net, ctx)
    f = components.AclFirewall(ctx.f, net, ctx)
    address_mappings = [(getattr(ctx, n), getattr(ctx, 'ip_%s'%(n))) for n in nodes]
    address_mappings.extend([(ctx.s0, ctx.ip_s0),
			     (ctx.cc, ctx.ip_cc),
			     (ctx.f, ctx.ip_f)])
    net.setAddressMappings(address_mappings)
    addresses = [getattr(ctx, addr) for addr in addresses]
    for host in hosts:
        net.RoutingTable(host, [(x, f) for x in addresses])
    net.RoutingTable(f, [(x, cc) for x in addresses])
    net.RoutingTable(cc, [( getattr(ctx, 'ip_%s'%(n)), getattr(ctx, n)) for n in nodes])
    net.RoutingTable(s0, [(x, cc) for x in addresses])
    rnodes = list(hosts)
    rnodes.append(f)
    rnodes.append(cc)
    rnodes.append(s0)

    acls = [(ctx.ip_s0, ctx.ip_n_0)]
    f.AddAcls(acls)
    net.Attach(*rnodes)
    class AclContentCacheReturn (object):
        def __init__ (self, net, ctx, cc, f, endhosts):
            self.net = net
            self.ctx = ctx
            self.cc = cc
            self.f = f
            self.s0 = s0
            self.endhosts = endhosts
            self.check = components.PropertyChecker (ctx, net)
    return AclContentCacheReturn(net, ctx, cc, f, hosts) 
