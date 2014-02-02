from mcnet.components import *
def FullModel ():
    parts = ['a', 'b', 'f', 'g']
    addresses = ['ip_%s'%(n) for n in parts]
    type_dict = {'a': EndHost, 'b': EndHost, 'g': EndHost, 'f': AclFirewall}
    ctx = Context(parts, addresses)
    routing = {'a': [(ctx.ip_b, ctx.f), (ctx.ip_g, ctx.g)], \
               'b': [(ctx.ip_a, ctx.f), (ctx.ip_g, ctx.g)], \
               'f': [(ctx.ip_a, ctx.a), (ctx.ip_b, ctx.b), (ctx.ip_g, ctx.g)], \
               'g': [(ctx.ip_a, ctx.a), (ctx.ip_b, ctx.b)]}
    net = Network(ctx)
    net.setAddressMappings([(getattr(ctx, n), getattr(ctx, a)) \
                           for n, a in zip(parts, addresses)])
    # Full model build all
    construct = list(parts)
    constructed = {}
    for c in construct:
        constructed[c] = type_dict[c](getattr(ctx, c), net, ctx)
        net.RoutingTable(constructed[c], routing[c])
    net.Attach(*constructed.values())
    class ReturnType (object):
        def __init__ (self, net, ctx, nodes):
            self.net = net
            self.ctx = ctx
            self.nodes = nodes
            self.solve = PropertyChecker(ctx, net)
    return ReturnType(net, ctx, constructed)
