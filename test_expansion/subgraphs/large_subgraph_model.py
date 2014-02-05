from mcnet.components import SubgraphProblem, EndHost, AclFirewall, Context, Network, LSRRRouter, LSRROption
def Subgraph02 (nlsrr):
    # Initialization
    lsrr_boxes = ['l%d'%(l) for l in xrange(nlsrr)]
    lsrr_address = ['ip_%s'%(l) for l in lsrr_boxes]
    firewalls = ['f0', 'f1', 'f2', 'f3', 'f4']
    f_address = ['ip_%s'%(f) for f in firewalls]
    endhosts = ['e0', 'e1', 'e2', 'e3', 'e4']
    e_address = ['ip_%s'%(e) for e in endhosts]

    nodes = list(lsrr_boxes)
    addresses = list(lsrr_address)

    nodes.extend(firewalls)
    addresses.extend(f_address)

    nodes.extend(endhosts)
    addresses.extend(e_address)

    ctx = Context(nodes, addresses)
    net = Network(ctx)

    net.setAddressMappings([(getattr(ctx, n), getattr(ctx, a)) \
                           for n, a in zip(nodes, addresses)])

    constructed = {}

    for eh in endhosts:
        constructed[eh] = EndHost(getattr(ctx, eh), net, ctx)

    for fidx in xrange(len(firewalls)):
        f = firewalls[fidx]
        constructed[f] = AclFirewall(getattr(ctx, f), net, ctx)
        ead = getattr(ctx, e_address[fidx])
        constructed[f].AddAcls([(ead, eother) for eother in xrange(len(endhosts)) if eother != fidx])

    # Register something that tells us about LSRR
    ip_lsr_field = LSRROption ('ip_lsr', ctx)
    ctx.AddPolicy (ip_lsr_field)

    for lsrr in lsrr_boxes:
        constructed[lsrr] = LSRRRouter (getattr(ctx, lsrr), ip_lsr_field, net, ctx)

    routing = {}
    eh_addresses = [getattr(ctx, a) for a in e_address]
    for i in xrange(len(endhosts)):
        node_routes = [(eh_addresses[j], constructed[firewalls[j]]) for j in xrange(len(endhosts)) if j != i]
        node_routes.extend([x for x in zip(map(lambda a:getattr(ctx, a), lsrr_address), \
                                       map(lambda n:constructed[n], lsrr_boxes))])
        routing[endhosts[i]] = node_routes
    for i in xrange(len(firewalls)):
        node_routes = [(eh_addresses[j], constructed[firewalls[j]]) for j in xrange(len(endhosts)) if j != i]
        node_routes.append((eh_addresses[i], constructed[endhosts[i]]))
        node_routes.extend([x for x in zip(map(lambda a:getattr(ctx, a), lsrr_address), \
                                       map(lambda n:constructed[n], lsrr_boxes))])
        routing[firewalls[i]] = node_routes
    lsrr_base_routes =[x for x in zip(map(lambda a:getattr(ctx, a), lsrr_address), \
                                       map(lambda n:constructed[n], lsrr_boxes))]
    lsrr_base_routes.extend([(eh_addresses[i], constructed[firewalls[i]]) for i in xrange(len(firewalls))])
    routing.update({n:lsrr_base_routes for n in lsrr_boxes})
    #for fidx

    prob = SubgraphProblem(ctx)
    prob.network = net
    prob.origin = constructed['e0']
    prob.target = constructed['e1']
    prob.node_map = constructed
    prob.tfunctions = routing
    return prob
