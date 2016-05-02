import components
import z3
from itertools import repeat
def IMCPlus(nservers):
    nodes = ['n%d'%i for i in xrange(nservers)]
    servers = list(nodes)

    nodes.append('lb1_o')
    nodes.append('lb2_o')
    lbs_out = ['lb1_o', 'lb2_o']

    nodes.append('lb1_i')
    nodes.append('lb2_i')
    lbs_in = ['lb1_i', 'lb2_i']
    nodes.append('dpi1')
    nodes.append('dpi2')
    dpis = ['dpi1', 'dpi2']
    nodes.append('fw1_o')
    nodes.append('fw2_o')
    fws_out = ['fw1_o', 'fw2_o']

    nodes.append('fw1_i')
    nodes.append('fw2_i')
    fws_in = ['fw1_i', 'fw2_i']

    nodes.append('cc1')
    ccs = ['cc1']

    addresses = ['i_%s'%n for n in nodes]
    ctx = components.Context(nodes, addresses)
    net = components.Network(ctx)
    # Make nodes
    all_nodes = []
    servers = [components.EndHost(getattr(ctx, s), net, ctx) for s in servers]  
    all_nodes += servers
    lbs_out = [components.AllowAll(getattr(ctx, s), net, ctx) for s in lbs_out]  
    all_nodes += lbs_out

    lbs_in = [components.AllowAll(getattr(ctx, s), net, ctx) for s in lbs_in]  
    all_nodes += lbs_in

    dpis = [components.AllowAll(getattr(ctx, s), net, ctx) for s in dpis]
    all_nodes += dpis

    fws_out = [components.AclFirewall(getattr(ctx, s), net, ctx) for s in fws_out]
    all_nodes += fws_out

    fws_in = [components.AclFirewall(getattr(ctx, s), net, ctx) for s in fws_in]
    all_nodes += fws_in

    ccs = [components.ContentCache(getattr(ctx, s), net, ctx) for s in ccs]
    all_nodes += ccs

    address_mapping = zip(nodes, addresses)
    address_mapping = map(lambda (n, a): (getattr(ctx, n), getattr(ctx, a)), \
                          address_mapping)
    net.Attach(*all_nodes)

    net.setAddressMappings(address_mapping)

    server_addresses = [getattr(ctx, 'i_%s'%s) for s in servers]
    # Server routing does not need to account for source.
    server_routing = []
    server0_routing = []
    for addr in server_addresses:
        server_routing.append((addr, components.not_failed(lbs_out[0]), lbs_out[0])) 
        server_routing.append((addr, components.failed(lbs_out[0]), lbs_out[1]))
        server0_routing.append((addr, ccs[0]))
    for s in servers[1:]:
        net.RoutingTableWithFailure(s, server_routing)
    net.RoutingTable(servers[0], server0_routing)

    ccs_routing = []
    ccs_routing.append((server_addresses[0], lambda t: True, servers[0]))
    for addr in server_addresses[1:]:
        ccs_routing.append((addr, components.not_failed(lbs_out[0]), lbs_out[0])) 
        ccs_routing.append((addr, components.failed(lbs_out[0]), lbs_out[1]))
    for cc in ccs:
        net.RoutingTableWithFailure(cc, ccs_routing) 

    lb_out_routing = []
    lb_in_routing = []
    # Special handling for server 0
    lb_in_routing.append((server_addresses[0], ccs[0]))
    lb_out_routing.append((server_addresses[0], components.not_failed(fws_out[0]), fws_out[0]))
    lb_out_routing.append((server_addresses[0], components.failed(fws_out[0]), fws_out[1]))
    for (addr, server) in zip(server_addresses[1:], servers[1:]):
        lb_in_routing.append((addr, server))
        lb_out_routing.append((addr, components.not_failed(fws_out[0]), fws_out[0]))
        lb_out_routing.append((addr, components.failed(fws_out[0]), fws_out[1]))

    for lb in lbs_in:
        net.RoutingTable(lb, lb_in_routing)

    for lb in lbs_out:
        net.RoutingTableWithFailure(lb, lb_out_routing)

    fw_out_routing = []
    fw_in_routing = []
    dpi_routing = []
    for addr in server_addresses:
        fw_in_routing.append((addr, components.not_failed(lbs_in[0]), lbs_in[0]))
        fw_in_routing.append((addr, components.failed(lbs_in[0]), lbs_in[1]))
        fw_out_routing.append((addr, components.not_failed(dpis[0]), dpis[0]))
        fw_out_routing.append((addr, components.failed(dpis[0]), dpis[1]))
        dpi_routing.append((addr, components.failed(fws_in[0]), fws_in[1]))
        dpi_routing.append((addr, components.not_failed(fws_in[0]), fws_in[0]))

    for fw in fws_out:
        net.RoutingTableWithFailure(fw, fw_out_routing)

    for fw in fws_in:
        net.RoutingTableWithFailure(fw, fw_in_routing)

    for dpi in dpis:
        net.RoutingTableWithFailure(dpi, dpi_routing)

    ad_map = dict([(str(x), y) for (x, y) in address_mapping])
    disallowed_address = []
    for n in fws_out:
        disallowed_address.append(ad_map[str(n)])
    for n in fws_in:
        disallowed_address.append(ad_map[str(n)])
    for n in lbs_in:
        disallowed_address.append(ad_map[str(n)])
    for n in lbs_out:
        disallowed_address.append(ad_map[str(n)])
    for n in dpis:
        disallowed_address.append(ad_map[str(n)])
    net.DisallowAddresses(disallowed_address)

    class IMCTopo(object):
        def __init__(self):
            self.servers = servers
            self.lbs_out = lbs_out
            self.lbs_in = lbs_in
            self.fws_out = fws_out
            self.fws_in = fws_in
            self.ccs = ccs
            self.dpis = dpis
            self.ctx = ctx
            self.network = net
            self.check = components.PropertyChecker(ctx, net)
            self.addresses = dict([(str(x), y) for (x, y) in address_mapping])
    return IMCTopo()
