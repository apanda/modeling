from . import NetworkObject, Core
import z3
class Fabric (NetworkObject):
    def _init (self, node, network, context):
        super(Fabric, self).init_fail(node)
        self.constraints = list ()
        self.node = node.z3Node
        self.ctx = context
        network.SaneSend(self)
        self.routing = []
        self._fabricSendRules()

    def _addConstraints (self, solver):
        solver.add(self.constraints)
        self._routeConstraints(solver)

    @property
    def z3Node (self):
        return self.node

    def AddRoutes (self, routes):
        """routes is (destination, node) list"""
        if not isinstance(routes, list):
            routes = [routes]
        self.routing.extend(routes)

    @property
    def Routes (self):
        return self.routing

    def _fabricSendRules(self):
        p_0 = z3.Const('%s_fabric_p_0'%(self.node), self.ctx.packet)
        n_0 = z3.Const('%s_fabric_n_0'%(self.node), self.ctx.node)
        n_1 = z3.Const('%s_fabric_n_1'%(self.node), self.ctx.node)
        t_0 = z3.Int('%s_fabric_t_0'%(self.node))
        t_1 = z3.Int('%s_fabric_t_1'%(self.node))

        self.constraints.append(z3.ForAll([n_0, p_0, t_0], z3.Implies(self.ctx.send(self.node, n_0, p_0, t_0), \
                                       z3.Exists([n_1, t_1], \
                                       z3.And(self.ctx.recv(n_1, self.node, p_0, t_1), \
                                              t_1 < t_0)))))
    def _routeConstraints(self, solver):
      p_0 = z3.Const('%s_fabric_p_0'%(self.node), self.ctx.packet)
      n_0 = z3.Const('%s_fabric_n_0'%(self.node), self.ctx.node)
      t_0 = z3.Int('%s_fabric_t_0'%(self.node))
      def route ((dest, node)):
        return z3.ForAll([n_0, p_0, t_0], \
                 z3.Implies(z3.And(self.ctx.send(self.node, n_0, p_0, t_0), \
                                   self.ctx.packet.dest(p_0) == dest), \
                            n_0 == node.z3Node))
      rc = map(route, self.routing)
      solver.add(rc)
