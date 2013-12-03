
import components
def withoutProxyAclFw ():
    """No proxy, just a learning firewall"""
    ctx = components.Context (['a', 'b', 'c', 'd', 'fw'],\
                              ['ip_a', 'ip_b', 'ip_c', 'ip_d', 'ip_f'])
    net = components.Network (ctx)
    a = components.EndHost(ctx.a, net, ctx) 
    b = components.EndHost(ctx.b, net, ctx) 
    c = components.EndHost(ctx.c, net, ctx) 
    d = components.EndHost(ctx.d, net, ctx) 
    fw = components.AclFirewall(ctx.fw, net, ctx)
    net.AdjacencyMap([(a, fw), (b, fw), (c, fw), (d, fw), (fw, [a, b, c, d])])
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (c, ctx.ip_c), \
                            (d, ctx.ip_d), \
                            (fw, ctx.ip_f)])
    addresses = [ctx.ip_a, ctx.ip_b, ctx.ip_c, ctx.ip_d, ctx.ip_f]
    net.RoutingTable(a, [(x, fw) for x in addresses])
    net.RoutingTable(b, [(x, fw) for x in addresses])
    net.RoutingTable(c, [(x, fw) for x in addresses])
    net.RoutingTable(d, [(x, fw) for x in addresses])

    net.RoutingTable(fw, [(ctx.ip_a, a), \
                          (ctx.ip_b, b), \
                          (ctx.ip_c, c), \
                          (ctx.ip_d, d)])
    fw.AddAcls([(ctx.ip_a, ctx.ip_c), (ctx.ip_c, ctx.ip_a), (ctx.ip_b, ctx.ip_d), (ctx.ip_d, ctx.ip_b)])
    net.Attach(a, b, c, d, fw)
    endhosts = [a, b, c, d]
    check = components.PropertyChecker(ctx, net)
    return (endhosts, check)
