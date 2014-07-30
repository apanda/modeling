# Basic fields and other things required for model checking.
import z3
from . import Core, DumbNode
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
        # Nodes in a network
        self.node, self.node_list = z3.EnumSort('Node', nodes)
        self.node_list = map(DumbNode, self.node_list)
        nodes = zip(nodes, self.node_list)
        for ndn, ndv in nodes:
            setattr(self, ndn, ndv)

        # Addresses for this network
        self.address, self.address_list = z3.EnumSort('Address', addresses)
        addresses = zip(addresses, self.address_list)
        for adn, adv in addresses:
            setattr(self, adn, adv)

        # Type for packets, contains (some of these are currently represented as relations):
        # -   src: Source address
        # -   dest: Destination address
        # -   origin: Node where the data originated. (Node)
        # -   body: Packet contents. (Integer)
        # -   seq: Sequence number for packets. (Integer)
        # -   options: A representation for IP options. (Integer)

        # TODO: Some of these are out, some of these are in.
        packet = z3.Datatype('Packet')
        packet.declare('packet', \
                       ('src', self.address), \
                       ('dest', self.address), \
                       ('origin', self.node), \
                       ('orig_body', z3.IntSort()), \
                       ('body', z3.IntSort()), \
                       ('seq', z3.IntSort()), \
                       ('options', z3.IntSort()))
        self.packet = packet.create()
        # $$src\_port: packet \rightarrow \mathbb{Z}^{+}$$
        self.src_port = z3.Function('sport', self.packet, z3.IntSort())
        # $$dest\_port: packet \rightarrow \mathbb{Z}^{+}$$
        self.dest_port = z3.Function('dport', self.packet, z3.IntSort())

        # Some commonly used relations
        # $$nodeHasAddr: node \rightarrow address \rightarrow boolean$$
        self.nodeHasAddr = z3.Function('nodeHasAddr', self.node, \
                                            self.address, z3.BoolSort ())
        # $$addrToNode: address \rightarrow node$$
        self.addrToNode = z3.Function('addrToNode', self.address, self.node)

        # Send and receive both have the form:
        # $$ source\rightarrow destination\rightarrow packet\rightarrow int\rightarrow bool$$
        # $$send: node \rightarrow node \rightarrow packet\rightarrow int\rightarrow bool$$
        self.send = z3.Function('send', self.node, self.node, self.packet, z3.IntSort(), z3.BoolSort())
        # $$recv: node \rightarrow node \rightarrow packet\rightarrow int\rightarrow bool$$
        self.recv = z3.Function('recv', self.node, self.node, self.packet, z3.IntSort(), z3.BoolSort())

        ## Forwarding table for how packets are forwarded.
        ## $$ftable: node\rightarrow packet\rightarrow node$$
        #self.ftable = z3.Function("ftable", self.node, self.packet, self.node)


    def _baseCondition (self):
        """ Set up base conditions for the network"""
        # Basic constraints for the overall model
        n_0 = z3.Const('ctx_base_n_0', self.node)
        n_1 = z3.Const('ctx_base_n_1', self.node)
        n_2 = z3.Const('ctx_base_n_2', self.node)
        n_3 = z3.Const('ctx_base_n_3', self.node)
        n_4 = z3.Const('ctx_base_n_4', self.node)
        p_0 = z3.Const('ctx_base_p_0', self.packet)
        t_0 = z3.Int('ctx_base_t_0')
        t_1 = z3.Int('ctx_base_t_1')

        # $$send(n_0, n_1, p_0, t_0) \Rightarrow n_0 \neq n_1$$
        self.constraints.append(
                z3.ForAll([n_0, n_1, p_0, t_0], \
                    z3.Implies(self.send(n_0, n_1, p_0, t_0), n_0 != n_1)))

        # $$recv(n_0, n_1, p_0, t_0) \Rightarrow n_0 \neq n_1$$
        self.constraints.append(
                z3.ForAll([n_0, n_1, p_0, t_0], \
                    z3.Implies(self.recv(n_0, n_1, p_0, t_0), n_0 != n_1)))

        # $$send(n_0, n_1, p_0, t_0) \Rightarrow p_0.src \neq p_0.dest$$
        self.constraints.append(
                z3.ForAll([n_0, n_1, p_0, t_0], \
                    z3.Implies(self.send(n_0, n_1, p_0, t_0), \
                                    self.packet.src(p_0) != self.packet.dest(p_0))))

        # $$recv(n_0, n_1, p_0, t_0) \Rightarrow p_0.src \neq p_0.dest$$
        self.constraints.append(
                z3.ForAll([n_0, n_1, p_0, t_0], \
                    z3.Implies(self.recv(n_0, n_1, p_0, t_0), \
                                    self.packet.src(p_0) != self.packet.dest(p_0))))

        # $$recv(n_0, n_1, p_0, t_0) \Rightarrow send(n_0, n_1, p_0, t_1) \land t_1 < t_0$$
        self.constraints.append(
                z3.ForAll([n_0, n_1, p_0, t_0], \
                    z3.Implies(self.recv(n_0, n_1, p_0, t_0), \
                                z3.Exists([t_1], \
                                   z3.And(self.send(n_0, n_1, p_0, t_1), \
                                        t_1 < t_0)))))
        # $$send(n_0, n_1, p_0, t_0) \Rightarrow p_0.src\_port > \land p_0.dest\_port < MAX_PORT$$
        self.constraints.append(
                z3.ForAll([n_0, n_1, p_0, t_0], \
                    z3.Implies(self.send(n_0, n_1, p_0, t_0), \
                                    z3.And(self.src_port(p_0) >= 0, \
                                            self.src_port(p_0) < Core.MAX_PORT))))
        # $$recv(n_0, n_1, p_0, t_0) \Rightarrow p_0.src\_port > \land p_0.dest\_port < MAX_PORT$$
        self.constraints.append(
                z3.ForAll([n_0, n_1, p_0, t_0], \
                    z3.Implies(self.recv(n_0, n_1, p_0, t_0), \
                                    z3.And(self.dest_port(p_0) >= 0, \
                                            self.dest_port(p_0) < Core.MAX_PORT))))
        # $$recv(n_0, n_1, p_0, t_0) \Rightarrow t_0 > 0$$
        self.constraints.append(
                z3.ForAll([n_0, n_1, p_0, t_0], \
                    z3.Implies(self.recv(n_0, n_1, p_0, t_0), \
                                   t_0 > 0))) 
        # $$send(n_0, n_1, p_0, t_0) \Rightarrow t_0 > 0$$
        self.constraints.append(
                z3.ForAll([n_0, n_1, p_0, t_0], \
                    z3.Implies(self.send(n_0, n_1, p_0, t_0), \
                                   t_0 > 0))) 


    def PacketsHeadersEqual (self, p1, p2):
        """Two packets have equal headers"""
        return z3.And(\
                self.packet.src(p1) == self.packet.src(p2), \
                self.packet.dest(p1) == self.packet.dest(p2), \
                self.packet.origin(p1) == self.packet.origin(p2), \
                self.packet.seq(p1) == self.packet.seq(p2), \
                self.src_port(p1) == self.src_port(p2), \
                self.dest_port(p1) == self.dest_port(p2), \
                self.packet.options(p1) == self.packet.options(p2))

    def PacketContentEqual (self, p1, p2):
        """Two packets have equal bodies"""
        return self.packet.body(p1) == self.packet.body(p2)

def failurePredicate (context):
    return lambda node:  z3.Not(context.failed (node.z3Node))

def destAddrPredicate (context, address):
    return lambda p: context.packet.dest(p) == address

def srcAddrPredicate (context, address):
    return lambda p: context.packet.src(p) == address
