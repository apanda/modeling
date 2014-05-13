import components
import z3
def TrivialSynth ():
    ctx = components.Context(['a', 'b', 'c', 'f'], \
                            ['ip_a', 'ip_b', 'ip_c', 'ip_f'])
    net = components.Network(ctx)
    a = components.EndHost(ctx.a, net, ctx) 
    b = components.EndHost(ctx.b, net, ctx) 
    c = components.EndHost(ctx.c, net, ctx) 
    f = components.AclFirewall(ctx.f, net, ctx)
    net.setAddressMappings([(a, ctx.ip_a), \
                            (b, ctx.ip_b), \
                            (c, ctx.ip_c),
                            (f, ctx.ip_f)])
    net.RoutingTable(a, [(ctx.ip_a, a), \
                         (ctx.ip_b, f),
                         (ctx.ip_c, f),
                         (ctx.ip_f, f)])
    net.RoutingTable(b, [(ctx.ip_a, f), \
                         (ctx.ip_b, b),
                         (ctx.ip_c, f),
                         (ctx.ip_f, f)])
    net.RoutingTable(c, [(ctx.ip_a, f), \
                         (ctx.ip_b, f),
                         (ctx.ip_c, c),
                         (ctx.ip_f, f)])
    net.RoutingTable(f, [(ctx.ip_a, a), \
                         (ctx.ip_b, b),
                         (ctx.ip_c, c),
                         (ctx.ip_f, f)])
    net.Attach(a, b, c, f)
    p = z3.Const('p', ctx.packet)
    #disallow_b_d = z3.ForAll([p], z3.Implies(ctx.packet.origin(p) == d.z3Node, ctx.etime(b.z3Node, p, ctx.recv_event) == 0))
    #allow_a_b = z3.ForAll([p], z3.Implies(z3.And(ctx.packet.origin(p) == a.z3Node, \
            #ctx.hostHasAddr(b.z3Node, ctx.packet.dest(p))), \
            #ctx.etime(b.z3Node, p, ctx.recv_event) >= ctx.etime(a.z3Node, p, ctx.send_event)))
    #const = [disallow_a_c, disallow_b_d, allow_a_b]
    p2 = z3.Const('p2', ctx.packet)
    const = []
    const.append(ctx.packet.src(p) == ctx.ip_a)
    const.append(ctx.packet.dest(p) == ctx.ip_c)
    const.append(ctx.packet.origin(p) == a.z3Node)
    const.append(ctx.etime(a.z3Node, p, ctx.send_event) > 0)
    const.append(ctx.etime(c.z3Node, p, ctx.recv_event) == 0)
    const.append(ctx.packet.src(p2) == ctx.ip_a)
    const.append(ctx.packet.dest(p2) == ctx.ip_b)
    const.append(ctx.packet.origin(p2) == a.z3Node)
    const.append(ctx.etime(a.z3Node, p2, ctx.send_event) > 0)
    const.append(ctx.etime(b.z3Node, p2, ctx.recv_event) > 0)
    class TrivialReturn (object):
        def __init__ (self, net, ctx, a, b, c, d, f):
            self.net = net
            self.ctx = ctx
            self.a = a
            self.b = b
            self.c = c
            self.d = d
            self.f = f
            self.constraints = const
            self.check = components.PropertyChecker (ctx, net)
    return TrivialReturn (net, ctx, a, b, c, None, f)
