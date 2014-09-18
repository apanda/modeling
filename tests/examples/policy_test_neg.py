import components
import itertools
def PolicyScaleNeg (naddress):
    nodes = ['a', 'b', 'f']
    
    a_address = ['ip_a%d'%(a) for a in xrange(naddress)]
    b_address = ['ip_b%d'%(b) for b in xrange(naddress)]
    
    addresses = ['ip_f']
    
    addresses.extend(a_address)
    addresses.extend(b_address)

    ctx = components.Context(nodes, addresses)
    net = components.Network(ctx)
    
    a = components.EndHost(ctx.a, net, ctx)
    b = components.EndHost(ctx.b, net, ctx)
    f = components.AclFirewall(ctx.f, net, ctx)
    
    net.SetIsolationConstraint(f, [a, b])
    net.SetGateway(a, f)
    net.SetGateway(b, f)
    a_addrs = map(lambda ad: getattr(ctx, ad), a_address) 
    b_addrs = map(lambda ad: getattr(ctx, ad), b_address) 
    net.setAddressMappings([(a, a_addrs), \
                            (b, b_addrs), \
                            (f, ctx.ip_f)])
    f_routing_table = [(addr, a) for addr in a_addrs]
    f_routing_table.extend([(addr, b) for addr in b_addrs])
    net.RoutingTable(f, f_routing_table)
    acls = list(itertools.product(a_addrs, b_addrs))
    f.AddAcls (acls)
    net.Attach(a, b, f)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, b, f):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.f = f
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, b, f)


