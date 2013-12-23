# Basic fields and other things required for model checking.
import z3
from . import Core
class Context(Core):
    """Context for all of the rest that follows. Every network needs one of
    these"""
    def  _init (self, nodes, addresses):
        self._mkTypes (nodes, addresses)
        self.constraints = list()
        self.policies = list ()
        self._baseCondition ()

    def AddPolicy (self, policy):
        """A policy is a collection of shared algorithms or functions used by multiple
           components (for instance compression or DPI policies etc)."""
        self.policies.append(policy)

    def _addConstraints (self, solver):
        solver.add(self.constraints)
        for policy in self.policies:
            policy._addConstraints (solver)

    def _mkTypes (self, nodes, addresses):
        # Networks have nodes, nodes are quite important
        self.node, self.node_list = z3.EnumSort('Node', nodes)
        nodes = zip(nodes, self.node_list)
        for ndn, ndv in nodes:
            setattr(self, ndn, ndv)
        
        # Also addresses for these nodes
        self.address, self.address_list = z3.EnumSort('Address', addresses)
        addresses = zip(addresses, self.address_list)
        for adn, adv in addresses:
            setattr(self, adn, adv)

        # Events we care about. Currently we just care about sending and receiving (events at active elements
        # are handled differently, c.f. learning firewall)
        self.events, [self.send_event, self.recv_event] = z3.EnumSort('Events', ['__ev_send', '__ev_recv'])

        # Networks have packets
        packet = z3.Datatype('Packet')
        packet.declare('packet', \
                       ('src', self.address), \
                       ('dest', self.address), \
                       ('origin', self.node), \
                       ('id', z3.IntSort()), \
                       ('seq', z3.IntSort()))
        self.packet = packet.create()

        # Some functions to keep everything running
        # hostHasAddr: self.node -> self.address -> boolean
        self.hostHasAddr = z3.Function('hostHasAddr', self.node, \
                                            self.address, z3.BoolSort ())
        # addrToHost: self.address -> self.node
        self.addrToHost = z3.Function('addrToHost', self.address, self.node)
        # send := src -> dst -> self.packet -> bool
        self.send = z3.Function('send', self.node, self.node, self.packet, z3.BoolSort ())
        # recv := src -> dst -> self.packet ->bool
        self.recv = z3.Function('recv', self.node, self.node, self.packet, z3.BoolSort ())
        # Time at which packet is processed
        # etime := node -> packet -> event -> int 
        self.etime = z3.Function('etime', self.node, self.packet, self.events, z3.IntSort ())
        self.src_port = z3.Function('sport', self.packet, z3.IntSort())
        self.dest_port = z3.Function('dport', self.packet, z3.IntSort())
        
        # Model failure
        # fail := node -> bool
        # TODO: Consider failure time
        self.failed = z3.Function('failure', self.node, z3.BoolSort())

    def PacketsHeadersEqual (self, p1, p2):
        """Return conditions that two packets have identical headers"""
        return z3.And(\
                self.packet.src(p1) == self.packet.src(p2), \
                self.packet.dest(p1) == self.packet.dest(p2), \
                self.packet.origin(p1) == self.packet.origin(p2), \
                self.packet.seq(p1) == self.packet.seq(p2), \
                self.src_port(p1) == self.src_port(p2), \
                self.dest_port(p1) == self.dest_port(p2))

    def _baseCondition (self):
        """ Set up base conditions for the network"""
        # A few temporary nodes
        eh1 = z3.Const('_base_eh1', self.node)
        eh2 = z3.Const('_base_eh2', self.node)
        eh3 = z3.Const('_base_eh3', self.node)
        eh4 = z3.Const('_base_eh4', self.node)
        # An self.address
        ad1 = z3.Const('_base_ad1', self.address)
        # And a self.packet
        p = z3.Const('__base_packet', self.packet)
        p2 = z3.Const('__base_packet_2', self.packet)
        # A host has address iff address belongs to host
        # \forall e_1 \in Node,\ a_1\in Address: hostHasAddr(e_1, a_1) \iff addrToHost(a_1) = e_1
        # self.constraints.append(z3.ForAll([eh1, ad1], self.hostHasAddr(eh1, ad1) == (self.addrToHost(ad1) == eh1)))

        # All sent packets are received
        # \forall e_1, e_2\in Node , p\in Packet: recv(e_1, e_2, p) \iff send(e_1, e_2, p)
        self.constraints.append (z3.ForAll([eh1, eh2, p], self.recv(eh1, eh2, p) ==  self.send(eh1, eh2, p)))
        
        # All received self.packets were once sent (don't invent self.packets).
        # \forall e_1, e_2, p: recv (e_1, e_2, p) \Rightarrow \exists e_3 send(addrToHost(p), e_3, p)
        self.constraints.append(z3.ForAll([eh1, eh2, p], z3.Implies(self.recv(eh1, eh2, p),
                                         z3.Exists([eh3], self.send(self.addrToHost(self.packet.src(p)), eh3, p)))))

        # Turn off loopback, loopback makes me sad
        # \forall e_1, e_2, p send(e_1, e_2, p) \Rightarrow e_1 \neq e_2
        # \forall e_1, e_2, p recv(e_1, e_2, p) \Rightarrow e_1 \neq e_2
        self.constraints.append(z3.ForAll([eh1, eh2, p], z3.Implies(self.send(eh1, eh2, p), eh1 != eh2)))
        self.constraints.append(z3.ForAll([eh1, eh2, p], z3.Implies(self.recv(eh1, eh2, p), eh1 != eh2)))

        # Rules for time
        # Received packets have time, don't receive before sent
        # \forall e_1, e_2, p: recv(e_1, e_2, p) \Rightarrow etime(e_2, p, R) >
        #                                 0 \land etime(e_2, p, R) > etime(e_1, p, S)
        self.constraints.append(z3.ForAll([eh1, eh2, p], z3.Implies(self.recv(eh1, eh2, p), z3.And(\
                            self.etime(eh2, p, self.recv_event) > 0, \
                            self.etime(eh2, p, self.recv_event) > self.etime(eh1, p, self.send_event)))))
        # All sent packets have an event time
        # \forall e_1, e_2, p: send(e_1, e_2, p) \Rightarrow etime(e_1, p, S) >
        #                             0 \land etime(e_2, p, R) > etime(e_1, p, S)
        self.constraints.append(z3.ForAll([eh1, eh2, p], z3.Implies(self.send(eh1, eh2, p), 
                            z3.And(self.etime(eh1, p, self.send_event) > 0, \
                            self.etime(eh2, p, self.recv_event) > self.etime(eh1, p, self.send_event)))))
        # Unreceved packets always have recv etime of 0
        # \forall e_1, p: (\notexists e_2: recv(e_2, e_1, p)) \Rightarrow etime(e_1, p, R) = 0
        self.constraints.append(z3.ForAll([eh1, p], z3.Implies(z3.Not(z3.Exists([eh2], self.recv(eh2, eh1, p))), \
                                    self.etime(eh1, p, self.recv_event) == 0)))
        # Unreceved packets always have send etime of 0
        # \forall e_1, p: (\notexists e_2: send(e_1, e_2, p)) \Rightarrow etime(e_1, p, S) = 0
        self.constraints.append(z3.ForAll([eh1, p], z3.Implies(z3.Not(z3.Exists([eh2], self.send(eh1, eh2, p))), \
                                    self.etime(eh1, p, self.send_event) == 0)))

        self.constraints.append(z3.ForAll([p], z3.And(self.src_port(p) > 0, self.src_port(p) < Core.MAX_PORT)))
        self.constraints.append(z3.ForAll([p], z3.And(self.dest_port(p) > 0, self.dest_port(p) < Core.MAX_PORT)))
        
        # No sends or recvs when failed.
        self.constraints.append(z3.ForAll([eh1], z3.Implies(self.failed(eh1), z3.Not(z3.ForAll([eh2, p], self.send(eh1, eh2, p))))))
        self.constraints.append(z3.ForAll([eh1], z3.Implies(self.failed(eh1), z3.Not(z3.ForAll([eh2, p], self.recv(eh2, eh1, p))))))

def failurePredicate (context):
    return lambda node:  z3.Not(context.failed (node.z3Node))

