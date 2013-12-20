import components
def TwoLearningFw ():
    """ A proxy and two firewalls. This results in a SAT result, i.e. the packet goes through
        since the proxy is used to send information through"""
    ctx = components.Context (['a', 'b', 'c', 'd', 'fw1', 'fw2', 'p'],\
                              ['ip_a', 'ip_b', 'ip_c', 'ip_d', 'ip_f1', 'ip_f2', 'ip_p'])
    net = components.Network (ctx)
    a = components.EndHost(ctx.a, net, ctx) 
    b = components.EndHost(ctx.b, net, ctx) 
    c = components.EndHost(ctx.c, net, ctx) 
    d = components.EndHost(ctx.d, net, ctx) 
    fw1 = components.AclFirewall(ctx.fw1, net, ctx)
    fw2 = components.AclFirewall(ctx.fw2, net, ctx)
    p = components.WebProxy(ctx.p, net, ctx)
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (c, ctx.ip_c), \
                            (d, ctx.ip_d), \
                            (fw1, ctx.ip_f1), \
                            (fw2, ctx.ip_f2), \
                            (p, ctx.ip_p)])
    addresses = [ctx.ip_a, ctx.ip_b, ctx.ip_c, ctx.ip_d, ctx.ip_f1, ctx.ip_f2]
    net.RoutingTable(a, [(x, fw1) for x in addresses])
    net.RoutingTable(b, [(x, fw1) for x in addresses])
    net.RoutingTable(c, [(x, fw2) for x in addresses])
    net.RoutingTable(d, [(x, fw2) for x in addresses])

    net.RoutingTable(fw1, [(ctx.ip_a, a), \
                          (ctx.ip_b, b), \
                          (ctx.ip_c, p), \
                          (ctx.ip_d, p), \
                          (ctx.ip_p, p), \
                          (ctx.ip_f2, p)])
    net.RoutingTable(fw2, [(ctx.ip_a, p), \
                         (ctx.ip_b, p), \
                         (ctx.ip_c, c), \
                         (ctx.ip_d, d), \
                         (ctx.ip_f1, p), \
                         (ctx.ip_p, p)])
    net.RoutingTable(p, [(ctx.ip_a, fw1), \
                         (ctx.ip_b, fw1), \
                         (ctx.ip_c, fw2), \
                         (ctx.ip_d, fw2), \
                         (ctx.ip_f1, fw1), \
                         (ctx.ip_f2, fw2)])
    fw1.AddAcls([(ctx.ip_a, ctx.ip_c), (ctx.ip_b, ctx.ip_d)])
    fw2.AddAcls([(ctx.ip_c, ctx.ip_a), (ctx.ip_d, ctx.ip_b)])
    net.Attach(a, b, c, d, fw1, fw2, p)
    endhosts = [a, b, c, d]
    check = components.PropertyChecker(ctx, net)
    return (endhosts, check)
