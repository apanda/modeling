from . import NetworkObject
import random
import z3

class PermutationMiddlebox (NetworkObject):
    """"""
    def _init (self, node, my_sources, sendable_addresses, network, context):
        self.sources = my_sources
        self.sendable = sendable_addresses
        self.node = node.z3Node
        self.net = network
        self.ctx = context
        self.constraints = []
        self.permute_map = {}
        self.functions()

    @property
    def z3Node (self):
        return self.node

    def PacketsEqualModSrc (self, p1, p2):
        """Return conditions that two packets have identical headers"""
        return z3.And(\
                self.ctx.packet.dest(p1) == self.ctx.packet.dest(p2), \
                self.ctx.packet.origin(p1) == self.ctx.packet.origin(p2), \
                self.ctx.packet.seq(p1) == self.ctx.packet.seq(p2), \
                self.ctx.src_port(p1) == self.ctx.src_port(p2), \
                self.ctx.dest_port(p1) == self.ctx.dest_port(p2), \
                self.ctx.packet.options(p1) == self.ctx.packet.options(p2), \
                self.ctx.packet.body(p1) == self.ctx.packet.body(p2))

    def _addConstraints (self, solver):
        solver.add(self.constraints)
        sp = z3.Const('sent_packet', self.ctx.packet)
        rp = z3.Const('recved_packet', self.ctx.packet)
        sh = z3.Const('sending_host', self.ctx.node)
        rh = z3.Const('recving_host', self.ctx.node)
        oh = z3.Const('other_host', self.ctx.node)
        solver.add(z3.ForAll([sp, sh], \
            z3.Implies(self.ctx.send(self.node, sh, sp),
               z3.And(z3.Exists([rp, rh], \
                  z3.And(\
                    self.ctx.recv(rh, self.node, rp), \
                    self.PacketsEqualModSrc(rp, sp), \
                    self.ctx.packet.src(sp) ==\
                         self.permute_src(self.ctx.packet.src(rp),
                              self.ctx.etime(self.node, rp, self.ctx.recv_event)),\
                    z3.Not(z3.Exists([oh], z3.And(self.ctx.send(self.node, oh, sp),
                                                  oh != sh))), \
                    self.ctx.etime(self.node, sp, self.ctx.send_event) > \
                       self.ctx.etime(self.node, rp, self.ctx.recv_event)))))))

    def functions (self):
        # Hash map for whether a packet has been received from a particular\
        self.has_received = z3.Function('has_recv_mb_%s'%(self.node), self.ctx.address, z3.IntSort(), z3.BoolSort())
        # Function to actually permute the source address.
        self.permute_src = z3.Function('perm_src_mb_%s'%(self.node), self.ctx.address, z3.IntSort(), self.ctx.address)
        a = z3.Const('mb_addr', self.ctx.address)
        t0 = z3.Int('has_recvd_time')
        t1 = z3.Int('recved_time')
        p = z3.Const('mb_packet', self.ctx.packet)
        self.constraints.append(z3.ForAll([a, t0], \
            z3.Implies(self.has_received(a, t0), \
              z3.And(
                t0 > 0, \
                z3.Exists([p, t1], \
                  z3.And(
                    t1 > 0, \
                    t0 > t1, \
                    self.ctx.etime(self.node, p, self.ctx.recv_event) == t1, \
                    self.ctx.packet.src(p)  == a
                ))))))
        #self.constraints.append(z3.ForAll([p, t0, t1], \
          #z3.Implies(
              #z3.And(t0 > 0, \
                     #self.ctx.etime(self.node, p, self.ctx.recv_event) == t0), \
              #z3.Or(t1 <= t0,
                    #self.has_received(self.ctx.packet.src(p), t1)))))
        other_addresses = self.sendable
        for adidx in xrange(0, len(other_addresses)):
            include = []
            address = other_addresses[adidx]
            while len(include) == 0:
                include = filter(lambda a:random.random() > 0.5,  other_addresses)
            self.permute_map[str(address)] = include
            condition = z3.And(map(lambda a: self.has_received(a, t0), include))
            self.constraints.append(z3.ForAll([t0],\
                z3.Implies(condition, \
                    self.permute_src(address, t0) == \
                        self.sources[adidx % len(self.sources)])))
            self.constraints.append(z3.ForAll([t0],\
                z3.Implies(z3.Not(condition), \
                    self.permute_src(address, t0) == address)))
        for ad in self.ctx.address_list:
            if str(ad) not in self.permute_map:
                self.constraints.append(z3.ForAll([t0],
                    self.permute_src(ad, t0) == ad))
