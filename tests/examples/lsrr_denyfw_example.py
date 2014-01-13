import components
import itertools

def LSRRDenyFwExample (size):
    left_nodes = [chr(c) for c in xrange(ord('a'), ord('a') + size)]
    right_nodes = [chr(c) for c in xrange(ord('a') + size, ord('a') + 2 * size)]
    end_hosts = ['e0', 'e1']
    firewalls = ['f0']

    all_nodes = []

    all_nodes.extend(left_nodes)
    all_nodes.extend(right_nodes)
    all_nodes.extend(end_hosts)
    all_nodes.extend(firewalls)
    addresses = ['ip_%s'%(n) for n in all_nodes]

    ctx = components.Context(all_nodes, addresses)
    net = components.Network(ctx)
    # Register something that tells us about LSR
    ip_lsr_field = components.LSRROption ('ip_lsr', ctx)
    ctx.AddPolicy (ip_lsr_field)

    end_hosts = [components.EndHost(getattr(ctx, e), net, ctx) for e in end_hosts]
    [e0, e1] = end_hosts
    firewalls = [components.AclFirewall(getattr(ctx, f), net, ctx) for f in firewalls]
    left_nodes =[components.LSRRRouter(getattr(ctx, l), ip_lsr_field, net, ctx) for l in left_nodes]
    right_nodes =[components.LSRRRouter(getattr(ctx, l), ip_lsr_field, net, ctx) for l in right_nodes]

    all_node_objects = []
    all_node_objects.extend(left_nodes)
    all_node_objects.extend(right_nodes)
    all_node_objects.extend(end_hosts)
    all_node_objects.extend(firewalls)

    addresses = [getattr(ctx, a) for a in addresses]
    address_map = [(o, a) for (o, a) in zip(all_node_objects, addresses)]
    net.setAddressMappings(address_map)

    firewalls[0].AddAcls([(ctx.ip_e0, ctx.ip_e1), \
                          (ctx.ip_e1, ctx.ip_e0)])
    #left_right_acls = [(getattr(ctx, 'ip_%s'%(ol.z3Node)), getattr(ctx, 'ip_%s'%(orr.z3Node))) \
                        #for (ol, orr) in itertools.product(left_nodes[:-1], right_nodes)]
    #right_left_acls = [(getattr(ctx, 'ip_%s'%(orr.z3Node)), getattr(ctx, 'ip_%s'%(ol.z3Node))) \
                        #for (ol, orr) in itertools.product(left_nodes[:-1], right_nodes)]

    firewalls[0].AddAcls([(getattr(ctx, 'ip_%s'%(left_nodes[-1].z3Node)), getattr(ctx, 'ip_%s'%(right_nodes[-1].z3Node)))])

    e0_routing_table = [(getattr(ctx, 'ip_%s'%(ol.z3Node)), ol) for ol in left_nodes]
    e0_routing_table.append((ctx.ip_e1, firewalls[0]))
    net.RoutingTable(e0, e0_routing_table)

    left_routing_table = [(getattr(ctx, 'ip_%s'%(orr.z3Node)), firewalls[0]) for orr in right_nodes]
    left_routing_table.append((ctx.ip_e0, e0))
    for ol in left_nodes:
        net.RoutingTable(ol, left_routing_table)

    right_routing_table = [(getattr(ctx, 'ip_%s'%(ol.z3Node)), firewalls[0]) for ol in left_nodes]
    right_routing_table.append((ctx.ip_e1, e1))
    for orr in right_nodes:
        net.RoutingTable(orr, right_routing_table)

    firewall_routing_table = [(a, o) for (a, o) in zip(addresses, all_node_objects)]
    net.RoutingTable(firewalls[0], firewall_routing_table)
    net.Attach(*all_node_objects)
    class LSRRReturn (object):
        def __init__ (self, net, ctx, **nodes):
            self.net = net
            self.ctx = ctx
            for k, v in nodes.iteritems():
                setattr(self, k, v)
            self.check = components.PropertyChecker (ctx, net)
    return LSRRReturn (net, ctx, **dict(zip(all_nodes, all_node_objects)))
