import components
from itertools import cycle

def PolicyIDSShuntTopo (npub, npriv, nquar, nids, nshunts):
    nhosts = npub + npriv + nquar
    nfirewalls = nids

    hosts = ['h%d'%(i) for i in xrange(nhosts)]
    host_addresses = ['ip_%s'%h for h in hosts]

    peering = ['p%d'%(i) for i in xrange(nids)]
    peering_addresses = ['ip_%s'%p for p in peering]

    idses = ['i%d'%(i) for i in xrange(nids)]
    ids_addresses = ['ip_%s'%i for i in idses]

    shunts = ['s%d'%(i) for i in xrange(nshunts)]
    shunt_addresses = ['ip_%s'%s for s in shunts]

    firewalls = ['f%d'%i for i in xrange(nfirewalls)]
    firewall_addresses = ['ip_%s'%f for f in firewalls]

    fabric = ['fab']
    fabric_address = ['ip_fab']

    secgroups = ['peering', 'pub', 'priv', 'quarantine']

    nodes = list(hosts)
    nodes.extend(peering)
    nodes.extend(idses)
    nodes.extend(shunts)
    nodes.extend(firewalls)
    nodes.extend(fabric)

    addresses = list(host_addresses)
    addresses.extend(peering_addresses)
    addresses.extend(ids_addresses)
    addresses.extend(shunt_addresses)
    addresses.extend(firewall_addresses)
    addresses.extend(fabric_address)

    ctx = components.Context(nodes, addresses)
    net = components.Network(ctx)
    sgpolicy = components.SecurityGroups("sgpolicy", secgroups, ctx, net) 

    address_mappings = []
    host_concrete = []
    for (host, address) in zip(hosts, host_addresses):
        host_concrete.append(components.EndHost(getattr(ctx, host), net, ctx))
        address_mappings.append((host_concrete[-1], getattr(ctx, address)))

    peering_concrete = []
    for (peer, address) in zip(peering, peering_addresses):
        peering_concrete.append(components.EndHost(getattr(ctx, peer), net, ctx))
        address_mappings.append((peering_concrete[-1], getattr(ctx, address)))

    shunt_concrete = []
    for (shunt, address) in zip(shunts, shunt_addresses):
        shunt_concrete.append(components.Scrubber(getattr(ctx, shunt), net, ctx))
        address_mappings.append((shunt_concrete[-1], getattr(ctx, address)))

    ids_concrete = []
    for (ids, address, shunt) in zip(idses, ids_addresses, cycle(shunt_concrete)):
        ids_concrete.append(components.SpreadIDS(getattr(ctx, ids), net, ctx, shunt))
        address_mappings.append((ids_concrete[-1], getattr(ctx, address)))

    fw_concrete = []
    for (fw, address) in zip(firewalls, firewall_addresses):
        fw_concrete.append(components.PolicyFirewall(getattr(ctx, fw), net, ctx, sgpolicy))
        address_mappings.append((fw_concrete[-1], getattr(ctx, address)))

    fabric_concrete = []
    for (fab, fad) in zip(fabric, fabric_address):
      fabric_concrete.append(components.Fabric(getattr(ctx, fab), net, ctx))
      address_mappings.append((fabric_concrete[-1], getattr(ctx, fad)))

    assert(len(fabric_concrete) == 1)
    
    net.setAddressMappings(address_mappings)
    
    # Set up routing

    for (peer, ids) in zip(peering_concrete, ids_concrete):
        net.SetIsolationConstraint(peer, [ids])

    for (ids, shunt, fw, peer, pa) in \
            zip(ids_concrete, cycle(shunt_concrete), fw_concrete, \
               peering_concrete, peering_addresses):
        net.SetIsolationConstraint(ids, [shunt, fw, peer])
        #for address in host_addresses:
        routing_table = []
        for a in host_addresses:
            routing_table.append((getattr(ctx, a), fw))
        routing_table.append((getattr(ctx, pa), peer)) 
        net.RoutingTableShunt(ids, routing_table, shunt)
        net.SetIsolationConstraint(fw, [ids, fabric_concrete[0]])
        net.SetIsolationConstraint(shunt, [ids, fabric_concrete[0]])

    for host in host_concrete:
        net.SetIsolationConstraint(host, [shunt, fabric_concrete[0]])

    # Compute routing tables
    for (host, fw) in zip(host_concrete[len(ids_concrete):], fw_concrete):
        routing_table = []
        for a in host_addresses:
            routing_table.append((getattr(ctx, a), fw))
        net.RoutingTable(host, routing_table)
  
    routing_table = []
    for (a, h) in zip(host_addresses, host_concrete):
        routing_table.append((getattr(ctx, a), h))
    for (a, ids) in zip(peering_addresses, ids_concrete):
        routing_table.append((getattr(ctx, a), ids))
    fabric_concrete[0].AddRoutes(routing_table)

    ## Compute ACLs
    policies = []
    # All reach pub
    policies.append((True, 'pub'))
    # Priv reach all
    policies.append(('priv', True))
    # Pub reach all
    policies.append(('pub', True))
    for fw in fw_concrete:
        fw.AddPolicies(policies)

    assignment = []
    #npub, npriv, nquar
    for paddr in peering_addresses:
        assignment.append((getattr(ctx, paddr), 'peering'))
    for haddr in host_addresses[:npub]:
        assignment.append((getattr(ctx, haddr), 'pub'))
    for haddr in host_addresses[npub : npub + npriv]:
        assignment.append((getattr(ctx, haddr), 'priv'))
    for haddr in host_addresses[npub + npriv : ]:
        assignment.append((getattr(ctx, haddr), 'quarantine'))
    sgpolicy.addAddressToGroup(assignment)

    net.Attach(*fabric_concrete)

    class SimpleIDSShuntRet (object):
        def __init__ (self):
            self.net = net
            self.ctx = ctx
            self.fws = fw_concrete
            self.shunts = shunt_concrete
            self.ids = ids_concrete

            self.pub = host_concrete[:npub]
            self.priv = host_concrete[npub:npub + npriv]
            self.quarantine = host_concrete[npub + npriv:]
            self.checker = components.PropertyChecker(ctx, net)

            self.sgpolicy = sgpolicy
            self.fabric = fabric_concrete[0]
            self.peers = peering_concrete
            self.nodes = []
            self.nodes.extend(self.fws)
            self.nodes.extend(self.shunts)
            self.nodes.extend(self.ids)
            self.nodes.extend(self.pub)
            self.nodes.extend(self.priv)
            self.nodes.extend(self.quarantine)
            self.nodes.extend(self.peers)
    return SimpleIDSShuntRet()
