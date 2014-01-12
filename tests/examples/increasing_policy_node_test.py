import components
def NumPolicyNodesTest (size):
    fws = ['f_%d'%(f) for f in xrange(0, 1)]
    # Start with 2 end hosts
    end_hosts = ['e_%d'%(e) for e in xrange(0, 2)]
    other_nodes = ['o_%d'%(o) for o in xrange(0, size)]
    all_nodes = []
    all_nodes.extend(end_hosts)
    all_nodes.extend(fws)
    all_nodes.extend(other_nodes)
    all_visible_nodes = []
    all_visible_nodes.extend(end_hosts)
    all_visible_nodes.extend(fws)
    addresses = ['ip_e_0', 'ip_e_1', 'ip_f_0']

    ctx = components.Context(all_nodes, addresses)
    net = components.Network(ctx)
    end_hosts = [components.EndHost(getattr(ctx, e), net, ctx) for e in end_hosts]
    firewalls = [components.NullNode(getattr(ctx, f), net, ctx) for f in fws]
    [e0, e1] = end_hosts
    all_node_objects = []
    all_node_objects.extend(end_hosts)
    all_node_objects.extend(firewalls)
    addresses = [getattr(ctx, ad) for ad in addresses]
    address_mappings = [(ob, ad) for (ob, ad) in zip([e0, e1, firewalls[0]], addresses)]
    net.setAddressMappings(address_mappings)

    """Topology
        e0   e1
          \  /
           d0            """

    for e in [end_hosts[0], end_hosts[1]]:
        net.SetGateway(e, firewalls[0])
    net.SetIsolationConstraint (firewalls[0], end_hosts)

    net.Attach(*all_node_objects)
    node_dict = dict(zip(all_visible_nodes, all_node_objects))
    class NumPolicyResult (object):
        def __init__ (self, net, ctx, **nodes):
            self.net = net
            self.ctx = ctx
            for k, v in nodes.iteritems():
                setattr(self, k, v)
            self.participants = nodes.values()
            self.check = components.PropertyChecker (ctx, net)
    return NumPolicyResult (net, ctx, **node_dict)
