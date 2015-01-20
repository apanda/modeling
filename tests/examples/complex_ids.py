import components
from itertools import repeat

def SimpleIDSShuntTopo (nhosts, nids):
    # Use different scrubbers for different idses
    nshunts = nids
    nfirewalls = nhosts - nids

    hosts = ['h%d'%(i) for i in xrange(nhosts)]
    host_addresses = ['ip_%s'%h for h in hosts]

    idses = ['i%d'%(i) for i in xrange(nids)]
    ids_addresses = ['ip_%s'%i for i in idses]

    shunts = ['s%d'%(i) for i in xrange(nshunts)]
    shunt_addresses = ['ip_%s'%s for s in shunts]


    firewalls = ['f%d'%i for i in xrange(nfirewalls)]
    firewall_addresses = ['ip_%s'%f for f in firewalls]

    nodes = list(hosts)
    nodes.extend(idses)
    nodes.extend(shunts)
    nodes.extend(firewalls)

    addresses = list(host_addresses)
    addresses.extend(ids_addresses)
    addresses.extend(firewall_addresses)
    addresses.extend(shunt_addresses)

    ctx = components.Context(nodes, addresses)
    net = components.Network(ctx)

    address_mappings = []
    host_concrete = []
    for (host, address) in zip(hosts, host_addresses):
        host_concrete.append(components.EndHost(getattr(ctx, host), net, ctx))
        address_mappings.append((host_concrete[-1], getattr(ctx, address)))

    shunt_concrete = []
    for (shunt, address) in zip(shunts, shunt_addresses):
        shunt_concrete.append(components.Scrubber(getattr(ctx, shunt), net, ctx))
        address_mappings.append((shunt_concrete[-1], getattr(ctx, address)))

    ids_concrete = []
    for (index, (ids, address)) in enumerate(zip(idses, ids_addresses)):
        ids_concrete.append(components.SpreadIDS(getattr(ctx, ids), net, ctx, shunt_concrete[index]))
        address_mappings.append((ids_concrete[-1], getattr(ctx, address)))

    fw_concrete = []
    for (fw, address) in zip(firewalls, firewall_addresses):
        fw_concrete.append(components.LearningFirewall(getattr(ctx, fw), net, ctx))
        address_mappings.append((fw_concrete[-1], getattr(ctx, address)))

    net.setAddressMappings(address_mappings)

    for (host, ids) in zip(host_concrete, ids_concrete):
        net.SetGateway(host, ids)

    # Compute routing tables
    for (host, fw) in zip(host_concrete[len(ids_concrete):], fw_concrete):
        routing_table = []
        for a in host_addresses:
            routing_table.append((getattr(ctx, a), fw))
        net.RoutingTable(host, routing_table)

    for (ids, shunt) in zip(ids_concrete, shunt_concrete):
        routing_table = []
        for (a, i) in zip(host_addresses, ids_concrete):
            if str(i) == str(ids):
                continue
            routing_table.append((getattr(ctx, a), i))
        for (a, f) in zip(host_addresses[nids:], fw_concrete):
            routing_table.append((getattr(ctx, a), f))
        net.RoutingTableShunt(ids, routing_table, shunt)

    for (fw, host, ha) in zip(fw_concrete, host_concrete[len(ids_concrete):], host_addresses[len(ids_concrete):]):
        routing_table = []
        routing_table.append((getattr(ctx, ha), host))
        for (a, i) in zip(host_addresses, ids_concrete):
            routing_table.append((getattr(ctx, a), i))
        for (a, f) in zip(host_addresses[nids:], fw_concrete):
            if str(f) == str(fw):
                continue
            routing_table.append((getattr(ctx, a), f))
        net.RoutingTable(fw, routing_table)

    for shunt in shunt_concrete:
        routing_table = []
        for (a, h) in zip(host_addresses, host_concrete):
            routing_table.append((getattr(ctx, a), h))
        net.RoutingTable(shunt, routing_table)

    # Compute ACLs
    fw_acls = []
    for a1 in host_addresses[:nids]:
        for a2 in host_addresses[nids:]:
            fw_acls.append((getattr(ctx, a1), getattr(ctx, a2)))
            fw_acls.append((getattr(ctx, a2), getattr(ctx, a1)))
    for fw in fw_concrete:
        #pass
        fw.AddAcls(fw_acls)

    #net.Attach(*host_concrete)
    #net.Attach(*ids_concrete)
    #net.Attach(*fw_concrete)
    #net.Attach(*shunt_concrete)

    class SimpleIDSShuntRet (object):
        def __init__ (self):
            self.net = net
            self.ctx = ctx
            self.fws = fw_concrete
            self.shunts = shunt_concrete
            self.ids = ids_concrete
            self.hosts = host_concrete
            self.checker = components.PropertyChecker(ctx, net)
    return SimpleIDSShuntRet()
