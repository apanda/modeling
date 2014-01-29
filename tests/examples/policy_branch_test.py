import components
import itertools
def PolicyScaleWithBranch (naddress, nbranches):
    nodes = ['a', 'b']
    firewalls = ['f_%d'%(f) for f in xrange(nbranches)]
    nodes.extend(firewalls)
    a_address = ['ip_a%d'%(a) for a in xrange(naddress)]
    b_address = ['ip_b%d'%(b) for b in xrange(naddress)]
    
    firewall_addresses = ['ip_%s'%(f) for f in firewalls]
    addresses = list()
    addresses.extend(firewall_addresses)
    addresses.extend(a_address)
    addresses.extend(b_address)

    ctx = components.Context(nodes, addresses)
    net = components.Network(ctx)
    
    a = components.EndHost(ctx.a, net, ctx)
    b = components.EndHost(ctx.b, net, ctx)
    fwalls = [components.AclFirewall(getattr(ctx, f), net, ctx) for f in firewalls]
    
    net.SetIsolationConstraint(a, fwalls)
    net.SetIsolationConstraint(b, fwalls)
    for f in fwalls:
        net.SetIsolationConstraint(f, [a, b])
    a_addrs = map(lambda ad: getattr(ctx, ad), a_address) 
    b_addrs = map(lambda ad: getattr(ctx, ad), b_address) 
    admappings = zip(fwalls, [getattr(ctx, ad) for ad in firewall_addresses])
    admappings.extend([(a, a_addrs), \
                       (b, b_addrs)])

    net.setAddressMappings(admappings)
    f_routing_table = [(addr, a) for addr in a_addrs]
    f_routing_table.extend([(addr, b) for addr in b_addrs])
    for f in fwalls:
        net.RoutingTable(f, f_routing_table)
    acls = list(itertools.product(a_addrs, b_addrs))
    for f in fwalls[:-1]:
        f.AddAcls (acls)
    fwalls[-1].AddAcls(acls[:-1])
    net.Attach(a, b, *fwalls)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, b, f):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.f = f
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, b, fwalls)


