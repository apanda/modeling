from . import Core
import z3

class SecurityGroups (Core):
    def _init (self, name, security_groups, ctx, net):
        """Name is used to name this oracle in z3. Allows multiple mappings """
        self.name = name
        self.constraints = list ()
        self.ctx = ctx
        self.net = net
        self.ctx.AddPolicy(self)
        # Tenants in this case is a list.
        self.sg_type, self.sg_list = \
                z3.EnumSort('%s_secgroup'%self.name, security_groups)
        self.sg_map = {}
        for (sg, value) in zip(security_groups, self.sg_list):
            self.sg_map[sg] = value
            setattr(self, sg, value)
        self.policy_func = z3.Function('%s'%(name), self.ctx.address, self.sg_type)
        self.address_sg_map = [] 
    
    def addAddressToGroup (self, sglist):
        def normalize ((addr, group)):
            if isinstance(group, str):
                group = self.sg_map[group]
            return (addr, group)
        sglist = map(normalize, sglist)
        self.address_sg_map.extend(sglist)

    def _addConstraints (self, solver):
        for (addr, group) in self.address_sg_map:
            solver.add(self.policy_func(addr) == group)

    def sgPredicate (self, group):
        if isinstance(group, str):
            group = self.sg_map[group]
        return lambda a: self.policy_func(a) == group
