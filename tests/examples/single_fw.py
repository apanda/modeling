import components
from itertools import repeat
def RonoDMZTest (ndmz, nhosts, nquarantine):
  """Some random real world test"""
  
  firewall = 'f'
  fw_address = 'ip_f'
  dmz_test_host = 'd1'
  dmz_test_addr = 'ip_d1'
  host_addresses = ['ip_h%d'%(i) for i in xrange(nhosts)]
  quarantine_addresses = ['ip_q%d'%(i) for i in xrange(nquarantine)]
  outside = 'o'
  outside_address = 'ip_o'
  nodes = [firewall, dmz_test_host, outside]
  addresses = [fw_address, dmz_test_addr, outside_address]
  addresses.extend(quarantine_addresses)
  addresses.extend(host_addresses)
  
  ctx = components.Context(nodes, addresses)
  net = components.Network (ctx)


  outside = components.EndHost(getattr(ctx, outside), net, ctx)
  
  dmz_test_host = components.EndHost(getattr(ctx, dmz_test_host), net, ctx)

  firewall = components.LearningFirewall(getattr(ctx, firewall), net, ctx)

  outside_address = getattr(ctx, outside_address)
  fw_address = getattr(ctx, fw_address)
  dmz_test_addr = getattr(ctx, dmz_test_addr)
  #net.SetGateway(outside, firewall)
  #net.SetGateway(dmz_test_host, firewall)
  net.RoutingTable(firewall, [(outside_address, outside), \
                       (dmz_test_addr, dmz_test_host)])
  net.RoutingTable(outside, [(outside_address, outside),
                             (dmz_test_addr, firewall)])
  net.RoutingTable(dmz_test_host, [(outside_address, firewall),
                             (dmz_test_addr, dmz_test_host)])
  net.setAddressMappings([(outside, outside_address), \
                          (firewall, fw_address), \
                          (dmz_test_host, dmz_test_addr)])

  for ad in quarantine_addresses:
    ad = getattr(ctx, ad)
    firewall.AddAcls([(ad, outside_address), (outside_address, ad)])
  
  for ad in host_addresses:
    ad = getattr(ctx, ad)
    firewall.AddAcls([(outside_address, ad)])
  
  net.Attach(outside, dmz_test_host, firewall)
  class DMZRet (object):
    def __init__ (self, outside, dmz, fw, ctx, net):
      self.outside = outside
      self.dmz = dmz
      self.fw = fw
      self.ctx = ctx
      self.net = net
      self.check = components.PropertyChecker(ctx, net)
  return DMZRet(outside, dmz_test_host, firewall, ctx, net)

def RonoQuarantineTest (ndmz, nhosts, nquarantine):
  """Some random real world test"""
  firewall = 'f'
  fw_address = 'ip_f'
  quarantine_test_host = 'q0'
  quarantine_test_addr = 'ip_q0'
  host_addresses = ['ip_h%d'%(i) for i in xrange(nhosts)]
  quarantine_addresses = ['ip_q%d'%(i) for i in xrange(1, nquarantine)]
  outside = 'o'
  outside_address = 'ip_o'
  nodes = [firewall, quarantine_test_host, outside]
  addresses = [fw_address, quarantine_test_addr, outside_address]
  addresses.extend(quarantine_addresses)
  addresses.extend(host_addresses)
  
  ctx = components.Context(nodes, addresses)
  net = components.Network (ctx)


  outside = components.EndHost(getattr(ctx, outside), net, ctx)
  
  quarantine_test_host = components.EndHost(getattr(ctx, quarantine_test_host), net, ctx)

  firewall = components.LearningFirewall(getattr(ctx, firewall), net, ctx)

  outside_address = getattr(ctx, outside_address)
  fw_address = getattr(ctx, fw_address)
  quarantine_test_addr = getattr(ctx, quarantine_test_addr)
  #net.SetGateway(outside, firewall)
  #net.SetGateway(dmz_test_host, firewall)
  net.RoutingTable(firewall, [(outside_address, outside), \
                       (quarantine_test_addr, quarantine_test_host)])
  net.RoutingTable(outside, [(outside_address, outside),
                             (quarantine_test_addr, firewall)])
  net.RoutingTable(quarantine_test_host, [(outside_address, firewall),
                             (quarantine_test_addr, quarantine_test_host)])
  net.setAddressMappings([(outside, outside_address), \
                          (firewall, fw_address), \
                          (quarantine_test_host, quarantine_test_addr)])
  firewall.AddAcls([(quarantine_test_addr, outside_address), \
                    (outside_address, quarantine_test_addr)])

  for ad in quarantine_addresses:
    ad = getattr(ctx, ad)
    firewall.AddAcls([(ad, outside_address), (outside_address, ad)])
  
  for ad in host_addresses:
    ad = getattr(ctx, ad)
    firewall.AddAcls([(outside_address, ad)])
  
  net.Attach(outside, quarantine_test_host, firewall)
  class QuarantineRet (object):
    def __init__ (self, outside, quarantine, fw, ctx, net):
      self.outside = outside
      self.quarantine = quarantine
      self.fw = fw
      self.ctx = ctx
      self.net = net
      self.check = components.PropertyChecker(ctx, net)
  return QuarantineRet(outside, quarantine_test_host, firewall, ctx, net)

def RonoHostTest (ndmz, nhosts, nquarantine):
  """Some random real world test"""
  firewall = 'f'
  fw_address = 'ip_f'
  test_host = 'h0'
  test_addr = 'ip_h0'
  host_addresses = ['ip_h%d'%(i) for i in xrange(1, nhosts)]
  quarantine_addresses = ['ip_q%d'%(i) for i in xrange(nquarantine)]
  outside = 'o'
  outside_address = 'ip_o'
  nodes = [firewall, test_host, outside]
  addresses = [fw_address, test_addr, outside_address]
  addresses.extend(quarantine_addresses)
  addresses.extend(host_addresses)
  
  ctx = components.Context(nodes, addresses)
  net = components.Network (ctx)


  outside = components.EndHost(getattr(ctx, outside), net, ctx)
  
  test_host = components.EndHost(getattr(ctx, test_host), net, ctx)

  firewall = components.LearningFirewall(getattr(ctx, firewall), net, ctx)

  outside_address = getattr(ctx, outside_address)
  fw_address = getattr(ctx, fw_address)
  test_addr = getattr(ctx, test_addr)
  #net.SetGateway(outside, firewall)
  #net.SetGateway(dmz_test_host, firewall)
  net.RoutingTable(firewall, [(outside_address, outside), \
                       (test_addr, test_host)])
  net.RoutingTable(outside, [(outside_address, outside),
                             (test_addr, firewall)])
  net.RoutingTable(test_host, [(outside_address, firewall),
                             (test_addr, test_host)])
  net.setAddressMappings([(outside, outside_address), \
                          (firewall, fw_address), \
                          (test_host, test_addr)])
  firewall.AddAcls([(outside_address, test_addr)])

  for ad in quarantine_addresses:
    ad = getattr(ctx, ad)
    firewall.AddAcls([(ad, outside_address), (outside_address, ad)])
  
  for ad in host_addresses:
    ad = getattr(ctx, ad)
    firewall.AddAcls([(outside_address, ad)])
  
  net.Attach(outside, test_host, firewall)
  class HostRet (object):
    def __init__ (self, outside, host, fw, ctx, net):
      self.outside = outside
      self.host = host
      self.fw = fw
      self.ctx = ctx
      self.net = net
      self.check = components.PropertyChecker(ctx, net)
  return HostRet(outside, test_host, firewall, ctx, net)

def NoRonoTest (ndmz, nhosts, nquarantine):
  """Some random real world test"""
  firewall = 'f'
  fw_address = 'ip_f'
  outside = 'o'
  outside_address = 'ip_o'
  hosts = ['h%d'%(i) for i in xrange(nhosts)]
  dmz = ['d%d'%(i) for i in xrange(ndmz)]
  quarantine = ['q%d'%(i) for i in xrange(nquarantine)]
  host_addresses = ['ip_%s'%(h) for h in hosts]
  dmz_addresses = ['ip_%s'%(d) for d in dmz]
  quarantine_addresses = ['ip_%s'%(q) for q in quarantine]
  
  nodes = [firewall, outside]
  nodes.extend(dmz)
  nodes.extend(quarantine)
  nodes.extend(hosts)

  addresses = [fw_address, outside_address]
  addresses.extend(host_addresses)
  addresses.extend(dmz_addresses)
  addresses.extend(quarantine_addresses)
  
  ctx = components.Context(nodes, addresses)
  net = components.Network(ctx)

  outside = components.EndHost(getattr(ctx, outside), net, ctx)
  outside_address = getattr(ctx, outside_address)

  firewall = components.LearningFirewall(getattr(ctx, firewall), net, ctx)
  fw_address = getattr(ctx, fw_address)

  hosts = [components.EndHost(getattr(ctx, host), net, ctx) for host in hosts]
  host_addresses = [getattr(ctx, ha) for ha in host_addresses]

  dmz = [components.EndHost(getattr(ctx, d), net, ctx) for d in dmz]
  dmz_addresses = [getattr(ctx, da) for da in dmz_addresses]

  quarantine = [components.EndHost(getattr(ctx, q), net, ctx) for q in quarantine]
  quarantine_addresses = [getattr(ctx, qa) for qa in quarantine_addresses]

  addressMap = [(firewall, fw_address), (outside, outside_address)]
  addressMap.extend(zip(hosts, host_addresses))
  addressMap.extend(zip(dmz, dmz_addresses))
  addressMap.extend(zip(quarantine, quarantine_addresses))
  net.setAddressMappings(addressMap)

  fw_routing_table = [(outside_address, outside), \
                      (fw_address, firewall)]
  fw_routing_table.extend(zip(host_addresses, hosts))
  fw_routing_table.extend(zip(dmz_addresses, dmz))
  fw_routing_table.extend(zip(quarantine_addresses, quarantine))
  net.RoutingTable(firewall, fw_routing_table)

  other_routing_table = [(outside_address, firewall), \
                         (fw_address, outside)]
  other_routing_table.extend([(ad, firewall) for ad in host_addresses])
  other_routing_table.extend([(ad, firewall) for ad in dmz_addresses])
  other_routing_table.extend([(ad, firewall) for ad in quarantine_addresses])

  net.RoutingTable(outside, other_routing_table)
  for host in hosts:
    net.RoutingTable(host, other_routing_table)
  for host in dmz:
    net.RoutingTable(host, other_routing_table)
  for host in quarantine:
    net.RoutingTable(host, other_routing_table)
  for ad in host_addresses:
    firewall.AddAcls([(outside_address, ad)])
  for ad in quarantine_addresses:
    firewall.AddAcls([(ad, outside_address), (outside_address, ad)])
  
  all_nodes = [outside, firewall]
  all_nodes.extend(hosts)
  all_nodes.extend(dmz)
  all_nodes.extend(quarantine)
  net.Attach(*all_nodes)
  class AllRet(object):
    def __init__ (self, outside, firewall, quarantine, hosts, dmz, ctx, net):
      self.outside = outside
      self.firewall = firewall
      self.quarantine = quarantine
      self.hosts = hosts
      self.dmz = dmz
      self.ctx = ctx
      self.net = net
      self.check = components.PropertyChecker(ctx, net)
  return AllRet(outside, firewall, quarantine, hosts, dmz, ctx, net)

def NoRonoTestPath (ndmz, nhosts, nquarantine, nrouters):
  """Some random real world test"""
  fws = ['f_%d'%(f) for f in xrange(0, nrouters)]
  fw_addresses = ['ip_%s'%(f) for f in fws]
  outside = 'o'
  outside_address = 'ip_o'
  hosts = ['h%d'%(i) for i in xrange(nhosts)]
  dmz = ['d%d'%(i) for i in xrange(ndmz)]
  quarantine = ['q%d'%(i) for i in xrange(nquarantine)]
  host_addresses = ['ip_%s'%(h) for h in hosts]
  dmz_addresses = ['ip_%s'%(d) for d in dmz]
  quarantine_addresses = ['ip_%s'%(q) for q in quarantine]
  
  nodes = [outside]
  nodes.extend(fws)
  nodes.extend(dmz)
  nodes.extend(quarantine)
  nodes.extend(hosts)

  addresses = [outside_address]
  addresses.extend(fw_addresses)
  addresses.extend(host_addresses)
  addresses.extend(dmz_addresses)
  addresses.extend(quarantine_addresses)
  
  ctx = components.Context(nodes, addresses)
  net = components.Network(ctx)

  outside = components.EndHost(getattr(ctx, outside), net, ctx)
  outside_address = getattr(ctx, outside_address)

  firewalls = [components.LearningFirewall(getattr(ctx, fw), net, ctx) for fw in fws]
  fw_addresses = [getattr(ctx, fw_address) for fw_address in fw_addresses]

  hosts = [components.EndHost(getattr(ctx, host), net, ctx) for host in hosts]
  host_addresses = [getattr(ctx, ha) for ha in host_addresses]

  dmz = [components.EndHost(getattr(ctx, d), net, ctx) for d in dmz]
  dmz_addresses = [getattr(ctx, da) for da in dmz_addresses]

  quarantine = [components.EndHost(getattr(ctx, q), net, ctx) for q in quarantine]
  quarantine_addresses = [getattr(ctx, qa) for qa in quarantine_addresses]

  addressMap = [(outside, outside_address)]
  addressMap.extend(zip(firewalls, fw_addresses))
  addressMap.extend(zip(hosts, host_addresses))
  addressMap.extend(zip(dmz, dmz_addresses))
  addressMap.extend(zip(quarantine, quarantine_addresses))
  net.setAddressMappings(addressMap)

  for fw_i in xrange(len(firewalls)):
      fw_routing_table = [(outside_address, outside) if fw_i == 0 else (outside_address, firewalls[fw_i - 1])]
      if fw_i + 1 == nrouters:
        fw_routing_table.extend(zip(host_addresses, hosts))
        fw_routing_table.extend(zip(dmz_addresses, dmz))
        fw_routing_table.extend(zip(quarantine_addresses, quarantine))
      else:
        fw_routing_table.extend(zip(host_addresses, repeat(firewalls[fw_i + 1])))
        fw_routing_table.extend(zip(dmz_addresses, repeat(firewalls[fw_i + 1])))
        fw_routing_table.extend(zip(quarantine_addresses, repeat(firewalls[fw_i + 1])))
      net.RoutingTable(firewalls[fw_i], fw_routing_table)

  other_routing_table = [(outside_address, outside)]
  other_routing_table.extend([(ad, firewalls[0]) for ad in host_addresses])
  other_routing_table.extend([(ad, firewalls[0]) for ad in dmz_addresses])
  other_routing_table.extend([(ad, firewalls[0]) for ad in quarantine_addresses])
  net.RoutingTable(outside, other_routing_table)

  other_routing_table = [(outside_address, firewalls[-1])]
  other_routing_table.extend([(ad, firewalls[-1]) for ad in host_addresses])
  other_routing_table.extend([(ad, firewalls[-1]) for ad in dmz_addresses])
  other_routing_table.extend([(ad, firewalls[-1]) for ad in quarantine_addresses])
  for host in hosts:
    net.RoutingTable(host, other_routing_table)
  for host in dmz:
    net.RoutingTable(host, other_routing_table)
  for host in quarantine:
    net.RoutingTable(host, other_routing_table)
  for ad in host_addresses:
    firewalls[0].AddAcls([(outside_address, ad)])
  for ad in quarantine_addresses:
    firewalls[0].AddAcls([(ad, outside_address), (outside_address, ad)])
  
  all_nodes = [outside]
  all_nodes.extend(firewalls)
  all_nodes.extend(hosts)
  all_nodes.extend(dmz)
  all_nodes.extend(quarantine)
  net.Attach(*all_nodes)
  class AllRet(object):
    def __init__ (self, outside, firewalls, quarantine, hosts, dmz, ctx, net):
      self.outside = outside
      self.firewall = firewalls
      self.quarantine = quarantine
      self.hosts = hosts
      self.dmz = dmz
      self.ctx = ctx
      self.net = net
      self.check = components.PropertyChecker(ctx, net)
  return AllRet(outside, firewalls, quarantine, hosts, dmz, ctx, net)
