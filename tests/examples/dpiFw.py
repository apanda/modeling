import components
def dpiFw ():
    """DPI Firewall. Everything is UNSAT since no bad packets make it through"""
    ctx = components.Context (['a', 'b', 'c', 'd', 'fw'],\
                              ['ip_a', 'ip_b', 'ip_c', 'ip_d', 'ip_f'])
    
    dpi_policy = components.DPIPolicy('hate_bad')
    ctx.AddPolicy (dpi_policy)

    net = components.Network (ctx)
    a = components.EndHost(ctx.a, net, ctx) 
    b = components.EndHost(ctx.b, net, ctx) 
    c = components.EndHost(ctx.c, net, ctx) 
    d = components.EndHost(ctx.d, net, ctx) 
    fw = components.IPS(dpi_policy, ctx.fw, net, ctx)
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
    #fw.AddAcls([(ctx.ip_a, ctx.ip_c), (ctx.ip_c, ctx.ip_a), (ctx.ip_b, ctx.ip_d), (ctx.ip_d, ctx.ip_b)])
    fw.AddAcls([(ctx.ip_a, ctx.ip_c), (ctx.ip_b, ctx.ip_d)])
    net.Attach(a, b, c, d, fw)
    endhosts = [a, b, c, d]
    check = components.PropertyChecker(ctx, net)
    return dict(ctx = ctx, net = net, endhosts = endhosts, policy = dpi_policy, check=check)
