import components
from itertools import repeat
def RonoDPITest (ndmz, nhosts, nquarantine):
  """Some random real world test"""
  
  dpi = 'f'
  fw_address = 'ip_f'
  dmz_test_host = 'd1'
  dmz_test_addr = 'ip_d1'
  host_addresses = ['ip_h%d'%(i) for i in xrange(nhosts)]
  quarantine_addresses = ['ip_q%d'%(i) for i in xrange(nquarantine)]
  outside = 'o'
  outside_address = 'ip_o'
  nodes = [dpi, dmz_test_host, outside]
  addresses = [fw_address, dmz_test_addr, outside_address]
  addresses.extend(quarantine_addresses)
  addresses.extend(host_addresses)
  
  ctx = components.Context(nodes, addresses)
  net = components.Network (ctx)

  outside = components.EndHost(getattr(ctx, outside), net, ctx)
  
  dmz_test_host = components.EndHost(getattr(ctx, dmz_test_host), net, ctx)

  dpi = components.DDOSProtection(getattr(ctx, dpi), net, ctx)

  outside_address = getattr(ctx, outside_address)
  fw_address = getattr(ctx, fw_address)
  dmz_test_addr = getattr(ctx, dmz_test_addr)
  net.RoutingTable(dpi, [(outside_address, outside), \
                       (dmz_test_addr, dmz_test_host)])
  net.RoutingTable(outside, [(outside_address, outside),
                             (dmz_test_addr, dpi)])
  net.RoutingTable(dmz_test_host, [(outside_address, dpi),
                             (dmz_test_addr, dmz_test_host)])
  net.setAddressMappings([(outside, outside_address), \
                          (dpi, fw_address), \
                          (dmz_test_host, dmz_test_addr)])

  net.Attach(outside, dmz_test_host, dpi)
  class DMZRet (object):
    def __init__ (self, outside, dmz, fw, ctx, net):
      self.outside = outside
      self.dmz = dmz
      self.fw = fw
      self.ctx = ctx
      self.net = net
      self.check = components.PropertyChecker(ctx, net)
  return DMZRet(outside, dmz_test_host, dpi, ctx, net)
