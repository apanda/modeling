import components
from itertools import cycle
def LinkTraversalScaling(size):
  firewalls = ['f0', 'f1', 'f2', 'f3']
  fw_addresses = ['ip_f0', 'ip_f1', 'ip_f2', 'ip_f3']
  assert(size > 2)
  hosts = ['e%d'%(n) for n in xrange(size)]
  host_addresses = ['ip_%s'%(h) for h in hosts]
  nodes = list(firewalls)
  nodes.extend(hosts)
  addresses = list(fw_addresses)
  addresses.extend(host_addresses)
  ctx = components.Context(nodes, addresses)
  net = components.Network (ctx)
  
  [f0, f1, f2, f3] = [components.AclFirewall(getattr(ctx, f), net, ctx) for f in firewalls]
  [ip_f0, ip_f1, ip_f2, ip_f3] = [getattr(ctx, f) for f in fw_addresses]
  hosts = [components.EndHost(getattr(ctx, h), net, ctx) for h in hosts]
  host_addresses = [getattr(ctx, h) for h in host_addresses]

  addr_mapping = list(zip(hosts, host_addresses))
  addr_mapping.extend([(f0, ip_f0), (f1, ip_f1), (f2, ip_f2), (f3, ip_f3)])
  net.setAddressMappings(addr_mapping)
  endhost_routing = [(h, f0) for h in host_addresses]
  for h in hosts:
    net.RoutingTable(h, endhost_routing)
  f1_f2_routing = [(h, f3) for h in host_addresses]
  net.RoutingTable(f1, f1_f2_routing)
  net.RoutingTable(f2, f1_f2_routing)
  f3_routing = [(a, h) for (a, h) in zip(host_addresses, hosts)]
  net.RoutingTable(f3, f3_routing)
  f0_routing = [(a, x) for (a, x) in zip(host_addresses, cycle([f1, f2]))]
  net.RoutingTable(f0, f0_routing)
  nodes = list(hosts)
  nodes.extend([f0, f1, f2, f3])
  net.Attach(*nodes)
  class LinkTraversalReturn (object):
    def __init__ (self, net, ctx, hosts, f0, f1, f2, f3):
      self.net = net
      self.ctx = ctx
      self.f0 = f0
      self.f1 = f1
      self.f2 = f2
      self.f3 = f3
      self.hosts = hosts
      self.check = components.PropertyChecker (ctx, net)
  return LinkTraversalReturn(net, ctx, hosts, f0, f1, f2, f3) 

