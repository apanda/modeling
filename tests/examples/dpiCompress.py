import components
def dpiCompress ():
    """DPI Firewall with some translation boxes. """
    ctx = components.Context (['a', 'b', 'c', 'd', 'fw', 'zip', 'uzip'],\
                              ['ip_a', 'ip_b', 'ip_c', 'ip_d', 'ip_f', 'ip_z', 'ip_u'])
    
    dpi_policy = components.DPIPolicy('hate_bad')
    ctx.AddPolicy (dpi_policy)
    gzip = components.CompressionAlgorithm('gzip')
    ctx.AddPolicy (gzip)

    net = components.Network (ctx)
    a = components.EndHost(ctx.a, net, ctx) 
    b = components.EndHost(ctx.b, net, ctx) 
    c = components.EndHost(ctx.c, net, ctx) 
    d = components.EndHost(ctx.d, net, ctx) 
    fw = components.IPS(dpi_policy, ctx.fw, net, ctx)
    zp = components.WANOptTransformer(gzip.compress, ctx.zip, net, ctx)
    uzp = components.WANOptTransformer(gzip.decompress, ctx.uzip, net, ctx)
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (c, ctx.ip_c), \
                            (d, ctx.ip_d), \
                            (fw, ctx.ip_f), \
                            (zp, ctx.ip_z), \
                            (uzp, ctx.ip_u)])
    addresses = [ctx.ip_a, ctx.ip_b, ctx.ip_c, ctx.ip_d, ctx.ip_f, ctx.ip_z, ctx.ip_u]
    net.RoutingTable(a, [(x, zp) for x in addresses])
    net.RoutingTable(b, [(x, zp) for x in addresses])
    net.RoutingTable(c, [(x, zp) for x in addresses])
    net.RoutingTable(d, [(x, zp) for x in addresses])

    net.RoutingTable(fw,  [(ctx.ip_a, uzp), \
                           (ctx.ip_b, uzp), \
                           (ctx.ip_c, uzp), \
                           (ctx.ip_d, uzp), \
                           (ctx.ip_z, zp), \
                           (ctx.ip_u, uzp)])

    net.RoutingTable(zp,  [(ctx.ip_a, fw), \
                           (ctx.ip_b, fw), \
                           (ctx.ip_c, fw), \
                           (ctx.ip_d, fw), \
                           (ctx.ip_f, fw), \
                           (ctx.ip_u, fw)])

    net.RoutingTable(uzp, [(ctx.ip_a, a), \
                           (ctx.ip_b, b), \
                           (ctx.ip_c, c), \
                           (ctx.ip_d, d), \
                           (ctx.ip_f, fw), \
                           (ctx.ip_z, fw)])
                           
    #fw.AddAcls([(ctx.ip_a, ctx.ip_c), (ctx.ip_c, ctx.ip_a), (ctx.ip_b, ctx.ip_d), (ctx.ip_d, ctx.ip_b)])
    fw.AddAcls([(ctx.ip_a, ctx.ip_c), (ctx.ip_b, ctx.ip_d)])
    net.Attach(a, b, c, d, fw)
    endhosts = [a, b, c, d]
    check = components.PropertyChecker(ctx, net)
    return dict(ctx = ctx, net = net, endhosts = endhosts, policy = dpi_policy, check=check, gzip=gzip)
