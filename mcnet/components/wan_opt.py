from . import NetworkObject, Core
import z3

class WANOptTransformer (NetworkObject):
    """Model a WAN optimizer that carries out some transformation. Transformations can include such things
       as compression and decompression"""
    def _init (self, transformation, node, network, context):
        """Algorithm represent a transformation algorithm (for instance GZip). We accept this
        as an input so we can have several boxes that share the same algorithm"""
        self.transformation = transformation
        self.transformer = node
        self.network = network
        self.ctx = context
        self.constraints = list()
        self._transformationSendRules ()

    @property
    def z3Node (self):
        return self.transformer

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def _transformationSendRules (self):
        # Compression boxes send out exactly one compressed packet for every incoming packet
        pi = z3.Const('_transformation_incoming_packet_%s'%(self.transformer), self.ctx.packet)
        po = z3.Const('_transformation_outgoing_packet_%s'%(self.transformer), self.ctx.packet)
        ni = z3.Const('__transformation_incoming_node_%s'%(self.transformer), self.ctx.node)
        no = z3.Const('__transformation_outgoing_node_%s'%(self.transformer), self.ctx.node)
        nb = z3.Const('__transformation_other_node_%s'%(self.transformer), self.ctx.node)
        
        # send(c, no, po) \Rightarrow \exists ni: recv(ni, c, pi) \land ....
        self.constraints.append(\
                z3.Implies(self.ctx.send(self.transformer, no, po), \
                    z3.And(z3.Exists([ni], self.ctx.recv(ni, self.transformer, pi)), \
                           self.ctx.packet.id(po) == \
                                    self.transformation(self.ctx.packet.id(pi)), \
                           self.ctx.PacketsHeadersEqual (po, pi), \
                           z3.Not(z3.Exists([nb], self.ctx.send(self.transformer, nb, po))), \
                           self.ctx.etime(self.transformer, pi, self.ctx.recv_event) <\
                                self.ctx.etime(self.transformer, po, self.ctx.send_event))))

