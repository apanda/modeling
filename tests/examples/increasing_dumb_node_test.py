import components
def NumDumbNodesTest (size):
    fws = ['f_%d'%(f) for f in xrange(0, size)]
    # Start with 4 end hosts
    end_hosts = ['e_%d'%(e) for e in xrange(0, 4)]
    all_nodes = []
    all_nodes.extend(end_hosts)
    all_nodes.extend(fws)

    addresses = ['ip_%s'%(n) for n in all_nodes]

    ctx = components.Context(all_nodes, addresses)
    net = components.Network(ctx)
    end_hosts = [components.EndHost(getattr(ctx, e), net, ctx) for e in end_hosts]
    firewalls = [components.NullNode(getattr(ctx, f), net, ctx) for f in fws]
    [e0, e1, e2, e3] = end_hosts
    all_node_objects = []
    all_node_objects.extend(end_hosts)
    all_node_objects.extend(firewalls)
    addresses = [getattr(ctx, ad) for ad in addresses]
    address_mappings = [(ob, ad) for (ob, ad) in zip(all_node_objects, addresses)]
    net.setAddressMappings(address_mappings)

    # This is a test that can be used for both positive and negative testing; one pair
    # of endhosts are allowed to send the other isn't
    acl_policy = [(ctx.ip_e_0, ctx.ip_e_1), (ctx.ip_e_1, ctx.ip_e_0)]
    """Topology
        e0          e1
          \        /
           f0 -- fn
          /        \
        e2          e3"""

    routing_table = [(ctx.ip_e_0, e0), \
                     (ctx.ip_e_2, e2), \
                     (ctx.ip_e_1, firewalls[-1]), \
                     (ctx.ip_e_3, firewalls[-1])]
    net.RoutingTable(firewalls[0], routing_table)

    routing_table = [(ctx.ip_e_0, firewalls[0]), \
                     (ctx.ip_e_2, firewalls[0]), \
                     (ctx.ip_e_1, e1), \
                     (ctx.ip_e_3, e3)]
    net.RoutingTable(firewalls[-1], routing_table)

    for e in [end_hosts[0], end_hosts[2]]:
        net.SetGateway(e, firewalls[0])

    for e in [end_hosts[1], end_hosts[3]]:
        net.SetGateway(e, firewalls[-1])

    net.Attach(*all_node_objects)
    node_dict = dict(zip(all_nodes, all_node_objects))
    class NumDumbResult (object):
        def __init__ (self, net, ctx, **nodes):
            self.net = net
            self.ctx = ctx
            for k, v in nodes.iteritems():
                setattr(self, k, v)
            self.check = components.PropertyChecker (ctx, net)
    return NumDumbResult (net, ctx, **node_dict)
