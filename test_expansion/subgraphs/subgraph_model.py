from mcnet.components import SubgraphProblem, EndHost, AclFirewall, Context, Network
def Subgraph01 ():
    parts = ['a', 'b', 'f0', 'f1', 'f2', 'g', 'h', 'i']
    addresses = ['ip_%s'%(n) for n in parts]
    ctx = Context(parts, addresses)
    routing = {'a': [(ctx.ip_b, ctx.f0), (ctx.ip_g, ctx.g)], \
               'b': [(ctx.ip_a, ctx.f0), (ctx.ip_g, ctx.g)], \
               'g': [(ctx.ip_a, ctx.a), (ctx.ip_b, ctx.b), (ctx.ip_h, ctx.f1), (ctx.ip_i, ctx.f2)], \
               'h': [(ctx.ip_a, ctx.f1), (ctx.ip_b, ctx.f1), (ctx.ip_g, ctx.f1)], \
               'i': [(ctx.ip_a, ctx.f2), (ctx.ip_b, ctx.f2), (ctx.ip_g, ctx.f2)], \
               'f0': [(ctx.ip_a, ctx.a), (ctx.ip_b, ctx.b), (ctx.ip_g, ctx.g)], \
               'f1': [(ctx.ip_a, ctx.f0), (ctx.ip_b, ctx.f0), (ctx.ip_g, ctx.g), (ctx.ip_h, ctx.h), (ctx.ip_i, ctx.f2)], \
               'f2': [(ctx.ip_a, ctx.f0), (ctx.ip_b, ctx.f0), (ctx.ip_g, ctx.g), (ctx.ip_h, ctx.f1), (ctx.ip_i, ctx.i)]}
    net = Network(ctx)
    net.setAddressMappings([(getattr(ctx, n), getattr(ctx, a)) \
                           for n, a in zip(parts, addresses)])

    constructed = \
            {'a': EndHost(ctx.a, net, ctx), \
             'b': EndHost(ctx.b, net, ctx), \
             'g': EndHost(ctx.g, net, ctx), \
             'h': EndHost(ctx.h, net, ctx), \
             'i': EndHost(ctx.i, net, ctx), \
             'f0': AclFirewall(ctx.f0, net, ctx), \
             'f1': AclFirewall(ctx.f1, net, ctx), \
             'f2': AclFirewall(ctx.f2, net, ctx)}
    constructed['f0'].AddAcls([(ctx.ip_a, ctx.ip_b)])
    prob = SubgraphProblem(ctx)
    prob.network = net
    prob.origin = 'a'
    prob.target = 'b'
    prob.node_map = constructed
    prob.tfunctions = routing
    return prob
