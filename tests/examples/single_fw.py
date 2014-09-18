import components
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
  class QuarantineRet (object):
    def __init__ (self, outside, host, fw, ctx, net):
      self.outside = outside
      self.host = host
      self.fw = fw
      self.ctx = ctx
      self.net = net
      self.check = components.PropertyChecker(ctx, net)
  return QuarantineRet(outside, test_host, firewall, ctx, net)
