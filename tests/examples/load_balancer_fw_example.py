import components
import itertools
def LoadBalancerFw (size):
    assert(size > 1)
    firewalls = ['f_%d'%(f) for f in xrange(size)]
    endhosts = ['e_%d'%(e) for e in xrange(4)]
    lbalancers = ['l_%d'%(l) for l in xrange(4)]

    all_nodes = list()
    all_nodes.extend(firewalls)
    all_nodes.extend(endhosts)
    all_nodes.extend(lbalancers)

    addresses = ['ip_%s'%(n) for n in all_nodes]

    ctx = components.Context(all_nodes, addresses)
    net = components.Network(ctx)

    endhosts = [components.EndHost(getattr(ctx, e), net, ctx) for e in endhosts]
    [e0, e1, e2, e3] = endhosts
    firewalls = [components.AclFirewall(getattr(ctx, f), net, ctx) for f in firewalls]
    lbalancers = [components.LoadBalancer(getattr(ctx, l), net, ctx) for l in lbalancers]

    all_node_objects = list()
    all_node_objects.extend(firewalls)
    all_node_objects.extend(endhosts)
    all_node_objects.extend(lbalancers)

    addresses = [getattr(ctx, a) for a in addresses]
    address_map = [(o, a) for (o, a) in zip(all_node_objects, addresses)]
    net.setAddressMappings(address_map)

    for i in xrange(4):
        net.SetIsolationConstraint(endhosts[i], [lbalancers[i]])
        lbalancer_nbr = [endhosts[i]]
        lbalancer_nbr.extend(firewalls)
        net.SetIsolationConstraint(lbalancers[i], lbalancer_nbr)
        lbalancer_routing = [(getattr(ctx, 'ip_%s'%(endhosts[j].z3Node)), firewalls) \
                               for j in xrange(4) if j != i]
        lbalancer_routing.append((getattr(ctx, 'ip_%s'%(endhosts[i].z3Node)), endhosts[i]))
        net.RoutingTable(lbalancers[i], lbalancer_routing)

    fw_routing_table = [(getattr(ctx, 'ip_%s'%(endhosts[i].z3Node)), lbalancers[i]) for i in xrange(4)]
    for fw in firewalls:
        net.RoutingTable(fw, fw_routing_table)
        net.SetIsolationConstraint(fw, lbalancers)
        fw.AddAcls([(ctx.ip_e_0, ctx.ip_e_1), \
                    (ctx.ip_e_2, ctx.ip_e_3)])
    net.Attach(*all_node_objects)
    class LoadBalancerFwReturn (object):
        def __init__ (self, net, ctx, **objdict):
            self.net = net
            self.ctx = ctx
            for k, v in objdict.iteritems():
                setattr(self, k, v)
            self.check = components.PropertyChecker (ctx, net)
    return LoadBalancerFwReturn(net, ctx, **dict(zip(all_nodes, all_node_objects)))
