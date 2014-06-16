import components
import itertools

def SymmetryTest1 (sz):
    assert (sz >= 1)
    a = ['a']
    endhosts = ['e%d'%(s) for s in xrange(sz)]
    firewall = ['f']
    nodes = list()
    nodes.extend(a)
    nodes.extend(endhosts)
    nodes.extend(firewall)
    addresses = ['ip_%s'%(n) for n in nodes]
    ctx = components.Context(nodes, addresses)
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx)
    endhosts = [components.EndHost(getattr(ctx, n), net, ctx) for n in endhosts]
    f = components.OneSidedFirewall(ctx.f, net, ctx)
    f.AddDeniedSources(ctx.ip_a)
    address_mappings = zip(map(lambda n: getattr(ctx, n), nodes), map(lambda a: getattr(ctx, a), addresses))
    net.setAddressMappings(address_mappings)
    net.SetGateway(a, f)
    endhost_pairs = map(lambda n: (getattr(ctx, 'ip_%s'%(n)), getattr(ctx, str(n))), endhosts)
    endhost_pairs.append((ctx.ip_a, ctx.a))
    net.RoutingTable(f, endhost_pairs)
    for n in endhosts:
        net.SetGateway(n, f)
    net.Attach(a, f, *endhosts)
    class SymmetricGroup (object):
      def __init__ (self, ctx, net, a, f, endhosts):
        self.ctx = ctx
        self.net = net
        self.a = a
        self.f = f
        self.endhosts = endhosts
        self.check = components.PropertyChecker(ctx, net)
    sym_ret = SymmetricGroup(ctx, net, a, f, endhosts)

    a = ['a']
    endhosts = ['e%d'%(s) for s in xrange(sz)]
    firewalls = ['f%d'%(s) for s in xrange(sz)]
    nodes = list()
    nodes.extend(a)
    nodes.extend(endhosts)
    nodes.extend(firewalls)
    addresses = ['ip_%s'%(n) for n in nodes]
    ctx = components.Context(nodes, addresses)
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx)
    endhosts = [components.EndHost(getattr(ctx, n), net, ctx) for n in endhosts]
    firewalls = [components.OneSidedFirewall(getattr(ctx, f), net, ctx) for f in firewalls]
    for firewall in firewalls:
        firewall.AddDeniedSources(ctx.ip_a)
    address_mappings = zip(map(lambda n: getattr(ctx, n), nodes), map(lambda a: getattr(ctx, a), addresses))
    net.setAddressMappings(address_mappings)
    e_f_pairs = zip(endhosts, firewalls)
    map(lambda (e, f): net.SetGateway(e, f), e_f_pairs)
    routing_pairs = map(lambda (e, f): (getattr(ctx, 'ip_%s'%(e)), f), e_f_pairs)
    net.RoutingTable(a, routing_pairs)
    for (e, f) in e_f_pairs:
        net.RoutingTable(f, [(getattr(ctx, 'ip_%s'%(e)), e), \
                          (ctx.ip_a, a)])
    net.Attach(a)
    net.Attach(*(firewalls + endhosts))
    class AsymmetricGroup (object):
      def __init__ (self, ctx, net, a, f, endhosts):
        self.ctx = ctx
        self.net = net
        self.a = a
        self.firewalls = f
        self.endhosts = endhosts
        self.check = components.PropertyChecker(ctx, net)
    asym_ret = AsymmetricGroup(ctx, net, a, firewalls, endhosts)
    return (sym_ret, asym_ret)
    #net.SetGateway(a, f)
    #endhost_pairs = map(lambda n: (getattr(ctx, 'ip_%s'%(n)), getattr(ctx, n)), endhosts)
    #endhost_pairs.append((ctx.ip_a, ctx.a))
    #net.RoutingTable(f, endhost_pairs)
    #for n in endhosts:
        #net.SetGateway(n, f)
    #net.attach(a, f, *endhosts)
    #class SymmetricGroup (object):
      #def __init__ (self, ctx, net, a, f, endhosts):
        #self.ctx = ctx
        #self.net = net
        #self.a = a
        #self.f = f
        #self.endhosts = endhosts
        #self.check = components.PropertyChecker(ctx, net)
    #sym_ret = SymmetricGroup(ctx, net, a, f, endhosts)

