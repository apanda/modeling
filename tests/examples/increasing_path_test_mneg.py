import components
def PathLengthTestMNeg (size, extra_rules):
    fws = ['f_%d'%(f) for f in xrange(0, size)]
    # Start with 4 end hosts
    end_hosts = ['e_%d'%(e) for e in xrange(0, 2)]
    all_nodes = []
    all_nodes.extend(end_hosts)
    all_nodes.extend(fws)

    addresses = ['ip_%s'%(n) for n in all_nodes]
    actual_addresses = list(addresses)
    additional_addresses = ['ip_d%d'%d for d in xrange(extra_rules)]
    actual_addresses.extend(additional_addresses)


    ctx = components.Context(all_nodes, actual_addresses)
    net = components.Network(ctx)
    end_hosts = [components.EndHost(getattr(ctx, e), net, ctx) for e in end_hosts]
    firewalls = [components.LearningFirewall(getattr(ctx, f), net, ctx) for f in fws]
    [e0, e1] = end_hosts
    all_node_objects = []
    all_node_objects.extend(end_hosts)
    all_node_objects.extend(firewalls)
    addresses = [getattr(ctx, ad) for ad in addresses]
    address_mappings = [(ob, ad) for (ob, ad) in zip(all_node_objects, addresses)]
    net.setAddressMappings(address_mappings)

    acl_policy = [(ctx.ip_e_0, getattr(ctx, ad)) for ad in additional_addresses]
    firewalls[0].AddAcls(acl_policy)
    acl_policy = [(ctx.ip_e_0, ctx.ip_e_1)]
    firewalls[0].AddAcls (acl_policy)

    """Topology
        e0                     e1
          \                   /
           f0 -- f1 -- .. -- fn"""

    for fw_i in xrange(len(firewalls)):
        routing_table = [(ctx.ip_e_0, firewalls[fw_i - 1] if fw_i > 0 else e0), \
                         (ctx.ip_e_1, firewalls[fw_i + 1] if fw_i + 1 < size else e1)]
        net.RoutingTable(firewalls[fw_i], routing_table)

    routing_table = [(ctx.ip_e_0, e0), \
                     (ctx.ip_e_1, firewalls[0])]
    net.RoutingTable(e0, routing_table)

    routing_table = [(ctx.ip_e_0, firewalls[-1]), \
                     (ctx.ip_e_1, e1)]
    net.RoutingTable(e1, routing_table)
    net.Attach(*all_node_objects)
    node_dict = dict(zip(all_nodes, all_node_objects))
    class NumFwResult (object):
        def __init__ (self, net, ctx, **nodes):
            self.net = net
            self.ctx = ctx
            for k, v in nodes.iteritems():
                setattr(self, k, v)
            self.check = components.PropertyChecker (ctx, net)
    return NumFwResult (net, ctx, **node_dict)
