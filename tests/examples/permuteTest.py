import components
def permuteTest (other_nodes):
    main_complex = ['a', 'b', 'm', 'fw']
    other_endhosts = ['e%d'%(i) for i in xrange(other_nodes)]
    other_permboxes = ['m%d'%(i) for i in xrange(other_nodes)]
    nodes = []
    nodes.extend(main_complex)
    nodes.extend(other_endhosts)
    nodes.extend(other_permboxes)
    main_eh_addresses = ['ip_a', 'ip_b']
    main_mb_addresses = ['ip_m%d'%(i) for i in xrange(0, 2 * other_nodes + 1)]
    other_mb_addresses = ['ip_om%d'%(i) for i in xrange(0, other_nodes)]
    other_eh_addresses = ['ip_%s'%(e) for e in other_endhosts]
    addresses = ['ip_f']
    addresses.extend(main_eh_addresses)
    addresses.extend(other_eh_addresses)
    addresses.extend(main_mb_addresses)
    addresses.extend(other_mb_addresses)
    ctx = components.Context (nodes,\
                              addresses)
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx) 
    b = components.EndHost(ctx.b, net, ctx) 
    main_mb_addresses = map(lambda ad: getattr(ctx, ad), main_mb_addresses)
    other_eh_addresses = map(lambda ad: getattr(ctx, ad), other_eh_addresses)
    other_mb_addresses = map(lambda ad: getattr(ctx, ad), other_mb_addresses)
    main_eh_addresses = map(lambda ad: getattr(ctx, ad), main_eh_addresses)
    other_addresses = []
    other_addresses.extend(other_mb_addresses)
    other_addresses.extend(other_eh_addresses)
    other_addresses.append(ctx.ip_a)

    m = components.PermutationMiddlebox(ctx.m, \
                        main_mb_addresses, \
                        other_addresses, \
                        net, \
                        ctx)
    fw = components.AclFirewall(ctx.fw, net, ctx)
    to_register = [a,b,m, fw]
    
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (fw, ctx.ip_f), \
                            (m, main_mb_addresses)])
    net.SetGateway(a, m)
    net.SetGateway(b, fw)

    other_endhosts = map(lambda eh: getattr(ctx, eh), other_endhosts)
    other_endhosts_eh = map(lambda eh: components.EndHost(eh, net, ctx), other_endhosts)
    net.setAddressMappings(zip(other_endhosts_eh, other_eh_addresses))
    to_register.extend(other_endhosts_eh)

    other_permboxes = map(lambda eh: getattr(ctx, eh), other_permboxes)
    other_pm_alt_addr = []
    other_pm_alt_addr.extend(other_eh_addresses)
    other_pm_alt_addr.extend(main_eh_addresses)
    other_permbox_addr_zip = zip(other_permboxes, other_mb_addresses)
    other_permbox_pm = map(lambda(n, a): components.PermutationMiddlebox(n, [a], 
                            other_pm_alt_addr, net, ctx), \
                            other_permbox_addr_zip)
    net.setAddressMappings(other_permbox_addr_zip)
    to_register.extend(other_permbox_pm)

    universal_routing = zip(other_eh_addresses, other_permbox_pm)
    universal_routing.append((ctx.ip_a, m))
    universal_routing.append((ctx.ip_b, m))

    for (node, mb) in zip(other_endhosts_eh, other_permbox_pm):
        net.RoutingTable(mb, universal_routing)
        net.SetGateway(node, mb)


    universal_routing = zip(other_eh_addresses, other_permbox_pm)
    m_routing = []
    m_routing.extend(universal_routing)
    m_routing.extend([(ctx.ip_a, a),
                         (ctx.ip_b, fw)])
    net.RoutingTable(m, m_routing)
    from itertools import repeat
    f_routing = []
    f_routing = zip(other_eh_addresses, repeat(m))
    f_routing.extend([(ctx.ip_a, m),
                          (ctx.ip_b, b),
                          (ctx.ip_m0, m)])
    net.RoutingTable(fw, f_routing)
    fw.AddAcls([(ctx.ip_a, ctx.ip_b)])
    fw.AddAcls(zip(main_mb_addresses, repeat(ctx.ip_b)))
    net.Attach(*to_register)
    class PReturn(object):
        def __init__ (self):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.m = m
            self.fw = fw
            self.check = components.PropertyChecker(ctx, net) 
            self.other_mb = other_permbox_pm
            self.other_eh = other_endhosts_eh
    return PReturn()
