import components
# Try making a trivial policy and see how well it works with this thing. The idea here
# is to just test this in a sandbox before moving onto richer more elegant ways of doing this

def TrivialPolicyTest (src, dest):
    """This policy test just uses a simple scheme of the following form:
       A - fw1 - p - fw2 - B
       C - fw3 / 
       
     src, dest are strings representing the source and destination between which we 
     want to test isolation between"""
    nodes = ['A', 'fw1', 'p', 'fw2', 'B', 'C', 'fw3']
    addresses = map(lambda n: 'a_%s'%(n), nodes)
    ctx = components.Context (nodes, addresses)
    net = components.Network (ctx)

    nodes_dict = {n : getattr(ctx, n) for n in nodes}
    address_dict = {a : getattr(ctx, a) for a in addresses}

    net.setAddressMappings([(nodes_dict[n], address_dict['a_%s'%(n)]) for n in nodes])
    
    # TODO: For now we cheat and just care about only one set. We can deal with several of them later
    assert (src == 'A')
    assert (dest == 'B')
    A = components.EndHost(ctx.A, net, ctx) 
    B = components.EndHost(ctx.B, net, ctx)
    fw1 = components.AclFirewall(ctx.fw1, net, ctx)
    fw2 = components.AclFirewall(ctx.fw2, net, ctx)
    p = components.WebProxy(ctx.p, net, ctx)
    net.SetGateway(A, fw1)
    net.SetGateway(B, fw2)

    net.RoutingTable(fw1, [(ctx.a_A, A),
                          (ctx.a_p, p),
                          (ctx.a_fw2, p),
                          (ctx.a_B, p),
                          (ctx.a_fw3, p),
                          (ctx.a_C, p)])

    net.RoutingTable(fw2, [(ctx.a_B, B),
                          (ctx.a_p, p),
                          (ctx.a_fw1, p),
                          (ctx.a_A, p),
                          (ctx.a_fw3, p),
                          (ctx.a_C, p)])

    net.RoutingTable(p, [(ctx.a_B, fw2),
                          (ctx.a_A, fw1),
                          (ctx.a_fw1, fw1),
                          (ctx.a_fw2, fw2)])
    fw1.AddAcls([(ctx.a_A, ctx.a_B), (ctx.a_B, ctx.a_A)])
    fw2.AddAcls([(ctx.a_A, ctx.a_B), (ctx.a_B, ctx.a_A)])
    net.SetIsolationConstraint(fw1, [A, p])
    net.SetIsolationConstraint(fw2, [B, p])
    net.SetIsolationConstraint(p, [fw1, fw2, ctx.fw3])
    net.Attach(A, B, fw1, fw2, p)
    check = components.PropertyChecker(ctx, net)
    print check.CheckIsolationProperty(A, B)
    return check, ctx
