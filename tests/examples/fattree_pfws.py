import components
from itertools import repeat
def PFWMultiTenantUnattach (tenant, external, internal):
  total_per_tenant = external + internal
  total = tenant * total_per_tenant
  hosts = ['h%d'%i for i in xrange(total)]
  host_addresses = ['ip_%s'%(i) for i in hosts]
  firewalls = ['f%d'%i for i in xrange(total)]
  fw_addresses = ['ip_%s'%(i) for i in firewalls]
  outside = []
  out_addresses = ['ip_%s'%i for i in outside]

  
  nodes = list(hosts)
  nodes.extend(firewalls)
  nodes.extend(outside)
  
  addresses = list(host_addresses)
  addresses.extend(fw_addresses)
  addresses.extend(out_addresses)

  ctx = components.Context(nodes, addresses)
  net = components.Network(ctx)

  priv_groups = ['priv_%d'%t for t in xrange(tenant)]
  pub_groups = ['pub_%d'%t for t in xrange(tenant)]
  sec_groups = priv_groups
  sec_groups.extend(pub_groups)
  sgpolicy = components.SecurityGroups("sgpolicy", sec_groups, ctx, net) 

  address_mappings = []
  host_concrete = []
  for (h, a) in zip(hosts, host_addresses):
    host_concrete.append(components.EndHost(getattr(ctx, h), net, ctx))
    address_mappings.append((host_concrete[-1], getattr(ctx, a)))
  
  firewall_concrete = []
  for (fw, a) in zip(firewalls, fw_addresses):
    firewall_concrete.append(components.PolicyFirewall(getattr(ctx, fw), net, ctx, sgpolicy))
    address_mappings.append((firewall_concrete[-1], getattr(ctx, a)))
  
  outside_concrete = []
  for (out, a) in zip(outside, out_addresses):
    outside_concrete.append(components.EndHost(getattr(ctx, out), net, ctx))
    address_mappings.append((outside_concrete[-1], getattr(ctx, a)))

  for (h, f) in zip(host_concrete, firewall_concrete):
    net.SetGateway(h, f)
  
  net.setAddressMappings(address_mappings)

  for (a, f, h) in zip(host_addresses, firewall_concrete, host_concrete):
    routing_table = [(getattr(ctx, a), h)]
    for (a2, f2) in zip(host_addresses, firewall_concrete):
      if str(f) == str(f2):
        continue
      routing_table.append((getattr(ctx, a2), f2))
    for (a2, o) in zip(out_addresses, outside_concrete):
      routing_table.append((getattr(ctx, a2), o))
    net.RoutingTable(f, routing_table)
  
  routing_table = []
  for (a, f) in zip(host_addresses, firewall_concrete):
    routing_table.append((getattr(ctx, a), f))
  for (a2, o) in zip(out_addresses, outside_concrete):
    routing_table.append((getattr(ctx, a2), o))
  for o in outside_concrete:
    net.RoutingTable(o, routing_table)


  # first internal hosts for each tenant are internals, rest are external
  for t in xrange(tenant):
    tbegin = t * total_per_tenant
    assignment = []
    for a in host_addresses[tbegin : tbegin + internal]:
      assignment.append((getattr(ctx, a), 'priv_%d'%(t)))
    for a in host_addresses[tbegin + internal : tbegin + total_per_tenant]:
      assignment.append((getattr(ctx, a), 'pub_%d'%(t)))
    sgpolicy.addAddressToGroup(assignment)

  for t in xrange(tenant):
    # The firewall is default deny, so we specify all the things that we allow in here.
    tbegin = t * total_per_tenant
    policies = []
    # Private to private
    policies.append(('priv_%d'%(t), 'priv_%d'%(t)))
    # Public to private
    policies.append(('pub_%d'%(t), 'priv_%d'%(t)))
    # Private to any
    policies.append(('priv_%d'%(t), True))
    # Public to any
    policies.append(('pub_%d'%(t), True))
    # Any to public
    policies.append((True, 'pub_%d'%(t)))
    for fw in firewall_concrete[tbegin:tbegin + total_per_tenant]:
      fw.AddPolicies(policies)
  class TennantRet (object):
    def __init__ (self):
      self.outside = outside_concrete
      self.hosts = host_concrete
      self.firewalls = firewall_concrete
      self.net = net
      self.ctx = ctx
      self.checker = components.PropertyChecker(ctx, net)
      self.sgroup = sgpolicy
  return TennantRet()
