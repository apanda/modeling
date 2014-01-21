import components

def LSRRFwTriv (sz):
    assert (sz >= 2)
    endhosts = ['e0', 'e1']
    lsrr_boxes = ['l_%d'%(l) for l in xrange(0, sz)]
    firewall = ['f']
    nodes = list()
    nodes.extend(endhosts)
    nodes.extend(lsrr_boxes)
    nodes.extend(firewall)
    addresses = ['ip_%s'%(c) for c in nodes]

    ctx = components.Context(nodes, \
                            addresses)
    net = components.Network(ctx)
    # Register something that tells us about LSR
    ip_lsr_field = components.LSRROption ('ip_lsr', ctx)
    ctx.AddPolicy (ip_lsr_field)
    e0 = components.EndHost(ctx.e0, net, ctx)
    e1 = components.EndHost(ctx.e1, net, ctx)
    ## Yeah I can put this in a list etc., doing it this way mostly for no good reason.
    #a = components.LSRRRouter (ctx.a, ip_lsr_field, net, ctx)
    #b = components.LSRRRouter (ctx.b, ip_lsr_field, net, ctx)
    lsrrs = [components.LSRRRouter (getattr(ctx, n), ip_lsr_field, net, ctx) for n in lsrr_boxes]
    lsrr_addresses = [getattr(ctx, 'ip_%s'%(l.z3Node)) for l in lsrrs]
    f = components.DenyingAclFirewall (ctx.f, net, ctx)
    address_mappings = [(e0, ctx.ip_e0), \
                        (e1, ctx.ip_e1), \
                          (f, ctx.ip_f)]
    lsrr_address_mappings = zip(lsrrs, lsrr_addresses)
    address_mappings.extend(lsrr_address_mappings)
    net.setAddressMappings(address_mappings)
    #net.setAddressMappings([(e0, ctx.ip_e0), \
                            #(e1, ctx.ip_e1), \
                            #(f, ctx.ip_f)])
    net.SetGateway(e0, lsrrs[0])
    net.SetGateway(e1, f)
    #f.AddAcls([(ctx.ip_e0, ctx.ip_e1), (ctx.ip_e1, ctx.ip_e0)])
    f.AddAcls([(lsrr_addresses[-1], ctx.ip_e1), (ctx.ip_e1, lsrr_addresses[0])])

    firewall_routing_table = [(ctx.ip_e0, lsrrs[-1]), (ctx.ip_e1, e1)]
    firewall_routing_table.extend([(ad, lsrrs[-1]) for ad in lsrr_addresses])
    net.RoutingTable(f, firewall_routing_table)

    lsrr_0_routing_table = [(ctx.ip_e0, e0), (ctx.ip_e1, lsrrs[1])]
    lsrr_0_routing_table.extend([(ad, lsrrs[1]) for ad in lsrr_addresses[1:]])
    net.RoutingTable (lsrrs[0], lsrr_0_routing_table)

    lsrr_l_routing_table = [(ctx.ip_e1, f), (ctx.ip_e0, lsrrs[-2])]
    lsrr_l_routing_table.extend([(ad, lsrrs[-2]) for ad in lsrr_addresses[:-1]])
    net.RoutingTable (lsrrs[-1], lsrr_l_routing_table)

    for idx in xrange(1, len(lsrrs) - 1):
        routing_table = [(ctx.ip_e0, lsrrs[idx - 1]), (ctx.ip_e1, lsrrs[idx + 1])]
        routing_table.extend([(ad, lsrrs[idx - 1]) for ad in lsrr_addresses[:idx]])
        routing_table.extend([(ad, lsrrs[idx + 1]) for ad in lsrr_addresses[idx + 1:]])
        net.RoutingTable (lsrrs[idx], routing_table)

    node_pairs = [('e0', e0), ('e1', e1), ('f', f)]
    node_pairs.extend (zip(lsrr_boxes, lsrrs))
    node_dict = dict(node_pairs)
    net.Attach(*node_dict.values())
    class LSRRReturn (object):
        def __init__ (self, net, ctx, **nodes):
            self.net = net
            self.ctx = ctx
            for k, v in nodes.iteritems():
                setattr(self, k, v)
            self.check = components.PropertyChecker (ctx, net)
    return LSRRReturn (net, ctx, **node_dict)
