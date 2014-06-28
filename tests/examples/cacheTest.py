import components
def cacheTest ():
    """ A proxy and a firewall. This results in a SAT result, i.e. the packet goes through
        since the proxy is used to send information through"""
    ctx = components.Context (['a', 'b', 'c', 'd', 'fw', 'p'],\
                              ['ip_a', 'ip_b', 'ip_c', 'ip_d', 'ip_f', 'ip_p'])
    net = components.Network (ctx)
    a = components.EndHost(ctx.a, net, ctx) 
    b = components.EndHost(ctx.b, net, ctx) 
    c = components.EndHost(ctx.c, net, ctx) 
    d = components.EndHost(ctx.d, net, ctx) 
    fw = components.AclFirewall(ctx.fw, net, ctx)
    p = components.ContentCache(ctx.p, net, ctx)
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (c, ctx.ip_c), \
                            (d, ctx.ip_d), \
                            (fw, ctx.ip_f), \
                            (p, ctx.ip_p)])
    addresses = [ctx.ip_a, ctx.ip_b, ctx.ip_c, ctx.ip_d, ctx.ip_f]
    net.SetGateway(a, p)
    net.SetGateway(b, p)
    net.SetGateway(c, p)
    net.SetGateway(d, p)

    #net.RoutingTable(a, [(x, fw) for x in addresses])
    #net.RoutingTable(b, [(x, fw) for x in addresses])
    #net.RoutingTable(c, [(x, p) for x in addresses])
    #net.RoutingTable(d, [(x, p) for x in addresses])

    net.RoutingTable(fw, [(ctx.ip_a, a), \
                          (ctx.ip_b, b), \
                          (ctx.ip_c, p), \
                          (ctx.ip_d, p), \
                          (ctx.ip_p, p)])
    net.RoutingTable(p, [(ctx.ip_a, a), \
                         (ctx.ip_b, b), \
                         (ctx.ip_c, c), \
                         (ctx.ip_d, d), \
                         (ctx.ip_f, fw)])
    fw.AddAcls([(ctx.ip_a, ctx.ip_c), (ctx.ip_b, ctx.ip_d)])
    net.Attach(a, b, c, d, fw, p)
    endhosts = [a, b, c, d]
    check = components.PropertyChecker(ctx, net)
    return (endhosts, check)
