from . import Core
import z3

class DPIPolicy (Core):
    """Policy for DPI boxes. Having a function per DPI box makes it hard to share policies"""
    def _init (self, policy_name):
        """Policy name is used to give unique names to the functions in z3"""
        self.name = policy_name
        self.body_sort = z3.BitVecSort(64)
        self.constraints = list ()
        self._createPolicyFunction ()

    def _createPolicyFunction (self):
        self.dpi_match = z3.Function('%s_dpi_match'%(self.name), self.body_sort, z3.BoolSort())
        some_content = z3.Const('__%s_dpi_content'%(self.name), self.body_sort)
        self.constraints.append(z3.Exists([some_content], self.dpi_match(some_content)))
        #self.constraints.append(z3.Exists([some_content], z3.Not(self.dpi_match(some_content))))

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def packetDPIPredicate (self, context):
        return lambda p: self.dpi_match(context.packet.orig_body(p))
