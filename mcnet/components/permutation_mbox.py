from . import NetworkObject
import random
import z3

class PermutationMiddlebox (NetworkObject):
    """"""
    def _init (self, node, my_sources, sendable_addresses, network, context):
        super(PermutationMiddlebox, self).init_fail(node)
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
        t0 = z3.Int('t0')
        t1 = z3.Int('t1')
        t2 = z3.Int('t1')
        solver.add(z3.ForAll([sp, sh, t0], \
            z3.Implies(self.ctx.send(self.node, sh, sp, t0),
               z3.And(z3.Exists([rp, rh], \
                  z3.And(\
                    self.ctx.recv(rh, self.node, rp, t1), \
                    self.PacketsEqualModSrc(rp, sp), \
                    self.ctx.packet.src(sp) ==\
                         self.permute_src(self.ctx.packet.src(rp),
                              t1),\
                    z3.Not(z3.Exists([oh, t2], z3.And(self.ctx.send(self.node, oh, sp, t2),
                                                  oh != sh))), \
                    t0 > t1))))))

    def functions (self):
        # Hash map for whether a packet has been received from a particular\
        self.has_received = z3.Function('has_recv_mb_%s'%(self.node), self.ctx.address, z3.IntSort(), z3.BoolSort())
        # Function to actually permute the source address.
        self.permute_src = z3.Function('perm_src_mb_%s'%(self.node), self.ctx.address, z3.IntSort(), self.ctx.address)
        a = z3.Const('mb_addr', self.ctx.address)
        t0 = z3.Int('has_recvd_time')
        t1 = z3.Int('recved_time')
        rh = z3.Const('recving_host', self.ctx.node)
        p = z3.Const('mb_packet', self.ctx.packet)
        self.constraints.append(z3.ForAll([a, t0], \
            z3.Implies(self.has_received(a, t0), \
              z3.And(
                t0 > 0, \
                z3.Exists([rh, p, t1], \
                  z3.And(
                    t1 > 0, \
                    t0 > t1, \
                    self.ctx.recv(self.node, rh, p,t1), \
                    self.ctx.packet.src(p)  == a
                ))))))
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
