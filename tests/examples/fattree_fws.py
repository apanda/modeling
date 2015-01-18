import components
from itertools import repeat

def FlatTenant (ext, internal):
  total = ext + internal
  hosts = ['h%d'%i for i in xrange(total)]
  host_addresses = ['ip_%s'%(i) for i in hosts]
  firewalls = ['f%d'%i for i in xrange(total)]
  fw_addresses = ['ip_%s'%(i) for i in firewalls]
  outside = ['o']
  out_addresses = ['ip_%s'%i for i in outside]
  
  nodes = list(hosts)
  nodes.extend(firewalls)
  nodes.extend(outside)
  
  addresses = list(host_addresses)
  addresses.extend(fw_addresses)
  addresses.extend(out_addresses)

  ctx = components.Context(nodes, addresses)
  net = components.Network(ctx)
  address_mappings = []
  host_concrete = []
  for (h, a) in zip(hosts, host_addresses):
    host_concrete.append(components.EndHost(getattr(ctx, h), net, ctx))
    address_mappings.append((host_concrete[-1], getattr(ctx, a)))
  
  firewall_concrete = []
  for (fw, a) in zip(firewalls, fw_addresses):
    firewall_concrete.append(components.LearningFirewall(getattr(ctx, fw), net, ctx))
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
  # first n hosts are internals
  for (idx, a, fw) in zip(range(internal), host_addresses, firewall_concrete):
    acls = []
    for out in out_addresses:
      acls.append((getattr(ctx, out), getattr(ctx, a)))
    fw.AddAcls(acls)
  net.Attach(*host_concrete)
  net.Attach(*firewall_concrete)
  net.Attach(*outside_concrete)
  class FlatTennantRet (object):
    def __init__ (self):
      self.outside = outside_concrete
      self.hosts = host_concrete
      self.firewalls = firewall_concrete
      self.net = net
      self.ctx = ctx
      self.checker = components.PropertyChecker(ctx, net)
  return FlatTennantRet()

def RichMultiTenant (tenant, external, internal):
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
  address_mappings = []
  host_concrete = []
  for (h, a) in zip(hosts, host_addresses):
    host_concrete.append(components.EndHost(getattr(ctx, h), net, ctx))
    address_mappings.append((host_concrete[-1], getattr(ctx, a)))
  
  firewall_concrete = []
  for (fw, a) in zip(firewalls, fw_addresses):
    firewall_concrete.append(components.LearningFirewall(getattr(ctx, fw), net, ctx))
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

  # first n hosts for each tenant are internals
  for t in xrange(tenant):
    tbegin = t * total_per_tenant
    for (idx, a, fw) in zip(range(internal), host_addresses[tbegin:],\
                                firewall_concrete[tbegin:]):
      acls = []
      for t2 in xrange(tenant):
        if t == t2:
          continue
        tbegin2 = t2 * total_per_tenant
        for out in host_addresses[tbegin2:tbegin2 + total_per_tenant]:
          acls.append((getattr(ctx, out), getattr(ctx, a)))
      fw.AddAcls(acls)
      

  net.Attach(*host_concrete)
  net.Attach(*firewall_concrete)
  class TennantRet (object):
    def __init__ (self):
      self.outside = outside_concrete
      self.hosts = host_concrete
      self.firewalls = firewall_concrete
      self.net = net
      self.ctx = ctx
      self.checker = components.PropertyChecker(ctx, net)
  return TennantRet()


def FlatTenantUnattach (ext, internal):
  total = ext + internal
  hosts = ['h%d'%i for i in xrange(total)]
  host_addresses = ['ip_%s'%(i) for i in hosts]
  firewalls = ['f%d'%i for i in xrange(total)]
  fw_addresses = ['ip_%s'%(i) for i in firewalls]
  outside = ['o']
  out_addresses = ['ip_%s'%i for i in outside]
  
  nodes = list(hosts)
  nodes.extend(firewalls)
  nodes.extend(outside)
  
  addresses = list(host_addresses)
  addresses.extend(fw_addresses)
  addresses.extend(out_addresses)

  ctx = components.Context(nodes, addresses)
  net = components.Network(ctx)
  address_mappings = []
  host_concrete = []
  for (h, a) in zip(hosts, host_addresses):
    host_concrete.append(components.EndHost(getattr(ctx, h), net, ctx))
    address_mappings.append((host_concrete[-1], getattr(ctx, a)))
  
  firewall_concrete = []
  for (fw, a) in zip(firewalls, fw_addresses):
    firewall_concrete.append(components.LearningFirewall(getattr(ctx, fw), net, ctx))
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
  # first n hosts are internals
  for (idx, a, fw) in zip(range(internal), host_addresses, firewall_concrete):
    acls = []
    for out in out_addresses:
      acls.append((getattr(ctx, a), getattr(ctx, out)))
      acls.append((getattr(ctx, out), getattr(ctx, a)))
    fw.AddAcls(acls)
  #net.Attach(*host_concrete)
  #net.Attach(*firewall_concrete)
  #net.Attach(*outside_concrete)
  class FlatTennantRet (object):
    def __init__ (self):
      self.outside = outside_concrete
      self.hosts = host_concrete
      self.firewalls = firewall_concrete
      self.net = net
      self.ctx = ctx
      self.checker = components.PropertyChecker(ctx, net)
  return FlatTennantRet()

def RichMultiTenantUnattach (tenant, external, internal):
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
  address_mappings = []
  host_concrete = []
  for (h, a) in zip(hosts, host_addresses):
    host_concrete.append(components.EndHost(getattr(ctx, h), net, ctx))
    address_mappings.append((host_concrete[-1], getattr(ctx, a)))
  
  firewall_concrete = []
  for (fw, a) in zip(firewalls, fw_addresses):
    firewall_concrete.append(components.LearningFirewall(getattr(ctx, fw), net, ctx))
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

  # first n hosts for each tenant are internals
  for t in xrange(tenant):
    tbegin = t * total_per_tenant
    for (idx, a, fw) in zip(range(internal), host_addresses[tbegin:],\
                                firewall_concrete[tbegin:]):
      acls = []
      for t2 in xrange(tenant):
        if t == t2:
          continue
        tbegin2 = t2 * total_per_tenant
        for out in host_addresses[tbegin2:tbegin2 + total_per_tenant]:
          #acls.append((getattr(ctx, a), getattr(ctx, out)))
          acls.append((getattr(ctx, out), getattr(ctx, a)))
      fw.AddAcls(acls)
  class TennantRet (object):
    def __init__ (self):
      self.outside = outside_concrete
      self.hosts = host_concrete
      self.firewalls = firewall_concrete
      self.net = net
      self.ctx = ctx
      self.checker = components.PropertyChecker(ctx, net)
  return TennantRet()
