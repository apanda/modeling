from . import NetworkObject
import z3
class LoadBalancer (NetworkObject):
    """Load balancers can be used to split traffic among multipler servers"""
    def _init (self, lbalancer, shared_addr, servers, context):
        self.constraints = list ()
        self.ctx = context
        self.lbalancer = lbalancer
        self.shared_addr = shared_addr
        self.servers = list()
        if servers:
            self.AddServers (servers)
        self.frozen = False

    def AddServers (self, servers):
        assert(not self.frozen)
        self.servers.extend(servers)

    def _addConstraints (self, solver):
        if not self.frozen:
            self.frozen = True
            self._loadBalancerRules(self.lbalancer, self.shared_addr, self.servers)
        solver.add(self.constraints)
    
    @property
    def z3Node (self):
        return self.lbalancer

    def _loadBalancerRules (self, lbalancer, shared_addr, servers):
        # No sane send, want to send out packets meant for me
        flow_hash_func = z3.Function('__lb_flowHashFunc_%s'%(lbalancer), self.ctx.packet, z3.IntSort())
        flow_hash_packet = z3.Const('__lb_fhash_packet1_%s'%(lbalancer), self.ctx.packet)
        self.constraints.append(z3.ForAll([flow_hash_packet], flow_hash_func(flow_hash_packet) < len(servers)))
        self.constraints.append(z3.ForAll([flow_hash_packet], flow_hash_func(flow_hash_packet) ==\
                                                        (self.ctx.dest_port(flow_hash_packet) + \
                                                        self.ctx.src_port(flow_hash_packet) % len(servers))))
       
        packet0 = z3.Const('__lb_packet1_%s'%(lbalancer), self.ctx.packet)
        node0 = z3.Const('__lb_node1_%s'%(lbalancer), self.ctx.node)
        node1 = z3.Const('__lb_node2_%s'%(lbalancer), self.ctx.node)
        # Load balancer does not invent packets
        self.constraints.append(z3.ForAll([node0, packet0], z3.Implies(self.ctx.send(lbalancer, node0, packet0), \
                z3.Exists([node1], \
                 z3.And(self.ctx.recv(node1, lbalancer, packet0), \
                 self.ctx.etime(lbalancer, packet0, self.ctx.recv_event) < \
                    self.ctx.etime(lbalancer, packet0, self.ctx.send_event))))))
        for idx, server in zip(range(len(servers)), servers):
            self.constraints.append(z3.ForAll([node0, packet0], z3.Implies(\
                  z3.And(\
                    self.ctx.recv(node0, lbalancer, packet0), \
                    self.ctx.packet.dest (packet0) == shared_addr, \
                    flow_hash_func (packet0) == idx),
                  z3.And(self.ctx.send(lbalancer, server, packet0),
                    self.ctx.etime(lbalancer, packet0, self.ctx.recv_event) < \
                        self.ctx.etime(lbalancer, packet0, self.ctx.send_event)))))
