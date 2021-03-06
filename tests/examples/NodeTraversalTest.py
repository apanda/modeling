import components
def NodeTraversalTest ():
    """ACL firewall test"""
    ctx = components.Context (['a', 'b', 'c', 'd', 'fw'],\
                              ['ip_a', 'ip_b', 'ip_c', 'ip_d', 'ip_f'])
    net = components.Network (ctx)
    a = components.EndHost(ctx.a, net, ctx) 
    b = components.EndHost(ctx.b, net, ctx) 
    c = components.EndHost(ctx.c, net, ctx) 
    d = components.EndHost(ctx.d, net, ctx) 
    fw = components.AclFirewall(ctx.fw, net, ctx)
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (c, ctx.ip_c), \
                            (d, ctx.ip_d), \
                            (fw, ctx.ip_f)])
    addresses = [ctx.ip_a, ctx.ip_b, ctx.ip_c, ctx.ip_d, ctx.ip_f]
    net.RoutingTable(a, [(x, fw) for x in addresses])
    net.RoutingTable(b, [(x, fw) for x in addresses])
    net.RoutingTable(c, [(x, fw) if str(x) != 'ip_a' else (x, a) for x in addresses])
    net.RoutingTable(d, [(x, fw) for x in addresses])
    #net.SetGateway(a, fw)
    #net.SetGateway(b, fw)
    #net.SetGateway(c, fw)
    #net.SetGateway(d, fw)

    net.RoutingTable(fw, [(ctx.ip_a, a), \
                          (ctx.ip_b, b), \
                          (ctx.ip_c, c), \
                          (ctx.ip_d, d)])
    fw.AddAcls([(ctx.ip_a, ctx.ip_b), (ctx.ip_c, ctx.ip_d)])
    net.Attach(a, b, c, d, fw)
    endhosts = [a, b, c, d]
    class AclFwReturn (object):
        def __init__ (self, net, ctx, a, b, c, d, fw):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.c = c
            self.d = d
            self.fw = fw
            self.check = components.PropertyChecker (ctx, net)
    return AclFwReturn(net, ctx, a, b, c, d, fw) 
