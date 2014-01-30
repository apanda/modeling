import components
import itertools

def LSRRFwTriv (sz):
    assert (sz >= 1)
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
    # Register something that tells us about LSRR
    ip_lsr_field = components.LSRROption ('ip_lsr', ctx)
    ctx.AddPolicy (ip_lsr_field)
    e0 = components.EndHost(ctx.e0, net, ctx)
    e1 = components.EndHost(ctx.e1, net, ctx)
    ## Yeah I can put this in a list etc., doing it this way mostly for no good reason.
    #a = components.LSRRRouter (ctx.a, ip_lsr_field, net, ctx)
    #b = components.LSRRRouter (ctx.b, ip_lsr_field, net, ctx)
    lsrrs = [components.LSRRRouter (getattr(ctx, n), ip_lsr_field, net, ctx) for n in lsrr_boxes]
    lsrr_addresses = [getattr(ctx, 'ip_%s'%(l.z3Node)) for l in lsrrs]
    f = components.AclFirewall (ctx.f, net, ctx)
    address_mappings = [(e0, ctx.ip_e0), \
                        (e1, ctx.ip_e1), \
                          (f, ctx.ip_f)]
    lsrr_address_mappings = zip(lsrrs, lsrr_addresses)
    address_mappings.extend(lsrr_address_mappings)
    net.setAddressMappings(address_mappings)
    routing_table_base = zip(lsrr_addresses, lsrrs)
    routing_table_base.append((ctx.ip_e0, e0))

    net.SetGateway(e1, f)

    f.AddAcls([(ctx.ip_e0, ctx.ip_e1)])
    f.AddAcls([(a, ctx.ip_e1) for a in lsrr_addresses[:-1]]) 

    f_routing_table = list(routing_table_base)
    f_routing_table.append((ctx.ip_e1, e1))
    net.RoutingTable(f, f_routing_table)

    routing_table_base.append((ctx.ip_e1, f))

    net.RoutingTable(e0, routing_table_base)
    for l in lsrrs:
        net.RoutingTable(l, routing_table_base)
    net.Attach(e0, e1, f, *lsrrs)
    class LSRRReturn (object):
        def __init__ (self, net, ctx, e0, e1, f, lsrrs):
            self.net = net
            self.ctx = ctx
            self.e0 = e0
            self.e1 = e1
            self.f = f
            self.lsrrs = lsrrs
            self.check = components.PropertyChecker (ctx, net)
    return LSRRReturn (net, ctx, e0, e1, f, lsrrs)
