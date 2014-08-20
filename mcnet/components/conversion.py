import z3
from . import Context
from collections import Iterable, defaultdict
class VariablesAndConstraint(object):
  def __init__(self, var, constraints):
    self.variables = var
    self.constraints = constraints
  def __repr__(self):
    return '%s<<%s>>'%(str(self.constraints), ','.join(map(str, self.variables)))
  def __str__(self):
    return self.__repr__()

class ModelContext(object):
  def __init__(self, name, context, time, node, packet):
    self.path_so_far = [True]
    self.vars_so_far = []
    self.implied_paths = defaultdict(lambda: [])
    self.implied_constraints = {} 
    self.time = time
    self.node = node
    self.packet = packet
    self.ctx = context

  def addPathConstraint(self, constraint, variables = []):
    self.vars_so_far.append(variables)
    self.path_so_far.append(constraint)

  def popPathConstraint(self):
    self.vars_so_far.pop()
    self.path_so_far.pop()

  def addCurrentImplication(self, implication, variables = []):
    implication = VariablesAndConstraint(variables, implication)
    self.implied_constraints[str(implication)] = implication
    path_vars = dict(map(lambda k: (str(k), k), [l for s in self.vars_so_far for l in s])).values()
    self.implied_paths[str(implication)].append(VariablesAndConstraint(path_vars, list(self.path_so_far)))

  def getAllConstraints(self):
    constraints = []
    for k, v in self.implied_constraints.iteritems():
      left_vars = v.variables
      right_pairs = self.implied_paths[k]
      right_constraint = []
      for right in right_pairs:
        right_vars = right.variables
        right_var_dict = dict(map(lambda k: (str(k), k), right_vars))
        left_var_dict = dict(map(lambda k: (str(k), k), left_vars))
        need_right = list(set(right_var_dict.keys()) - set(left_var_dict.keys()))
        right_vars = [right_var_dict[k] for k in need_right]
        if len(right_vars) > 0:
          right_constraint.append(\
            z3.Exists(right_vars, \
               z3.And(right.constraints)))
        else:
          right_constraint.append(z3.And(right.constraints))
      constraint = z3.ForAll(left_vars, \
              z3.Implies(v.constraints, \
                 z3.Or(right_constraint)))
      constraints.append(constraint)
    return constraints

def ModelForward (mcontext):
  fnode = z3.Const('%s_f_n'%(mcontext.node), mcontext.ctx.node)
  pconstraint = mcontext.ctx.send(mcontext.node.z3Node, \
                   fnode, \
                   mcontext.packet,\
                   mcontext.time)
  mcontext.addCurrentImplication(pconstraint, [fnode, mcontext.packet, mcontext.time])

def ModelSend (mcontext, packet_constraints):
  fnode = z3.Const('%s_s_n'%(mcontext.node), mcontext.ctx.node)
  packet = z3.Const('%s_s_p'%(mcontext.node), mcontext.ctx.packet)
  for constraint in packet_constraints:
    c = constraint(packet)
    if not isinstance(c, Iterable):
      c = [c]
    mcontext.addPathConstraint(*c)
  pconstraint = mcontext.ctx.send(mcontext.node.z3Node, \
                                  fnode, \
                                  packet, \
                                  mcontext.time)
  mcontext.addCurrentImplication(pconstraint, [fnode, packet, mcontext.time])
  for constraint in packet_constraints:
    mcontext.popPathConstraint()

def ModelRecv (mcontext):
  rtime = z3.Int('%s_r_t'%(mcontext.node))
  rnode = z3.Const('%s_r_n'%(mcontext.node), mcontext.ctx.node)
  pconstraint = z3.And(mcontext.ctx.recv(rnode, 
                   mcontext.node.z3Node, \
                   mcontext.packet,\
                   rtime),
                rtime < mcontext.time)
  mcontext.addPathConstraint(pconstraint, [rtime, rnode, mcontext.packet])

class ConfigMap(object):
  def __init__(self, name, mcontext, KTypes, VType):
    if not isinstance(KTypes, Iterable):
      types = [KTypes]
    else:
      types = list(KTypes)
    types.append(VType)
    self.map_func = z3.Function(name, *types)
    self.name = name
    self.mcontext = mcontext
  def __getitem__ (self, key):
    if not isinstance(key, Iterable):
      key = [key]
    else:
      key = list(key)
    return self.map_func(*key)
  def set (self, key, value):
    if not isinstance(key, Iterable):
      key = [key]
    else:
      key = list(key)
    return lambda : self.mcontext.addCurrentImplication(self.map_func(*key) == value)

class ModelMap(object):
  def __init__(self, name, mcontext, KTypes, VType):
    if not isinstance(KTypes, Iterable):
      types = [KTypes]
    else:
      types = list(KTypes)
    types.append(z3.IntSort())
    types.append(VType)
    self.map_func = z3.Function(name, *types)
    self.name = name
    self.mcontext = mcontext
  def __getitem__ (self, key):
    if not isinstance(key, Iterable):
      key = [key]
    else:
      key = list(key)
    key.append(self.mcontext.time)
    return self.map_func(*key)
  def set (self, key, value):
    if not isinstance(key, Iterable):
      key = [key]
    else:
      key = list(key)
    t = z3.Int('map_%s_t'%(self.name))
    key.append(t)
    return lambda : self.mcontext.addCurrentImplication(z3.And(
                            t > self.mcontext.time, \
                            self.map_func(*key) == value),
                            [t])

def If(mcontext, cond, body, else_body = None):
  mcontext.addPathConstraint(cond)
  if not isinstance(body, Iterable):
    body = [body]
  for statement in body:
    statement()
  mcontext.popPathConstraint()
  if else_body:
    mcontext.addPathConstraint(z3.Not(cond))
    if not isinstance(else_body, Iterable):
      else_body = [else_body]
    for statement in else_body:
      mcontext.addCurrentImplication(statement())
    mcontext.popPathConstraint()

def FwModel(mc):
  acl = ConfigMap('acl', mc, [mc.ctx.address, mc.ctx.address], z3.BoolSort())
  ModelRecv(mc)
  If(mc, acl[(mc.ctx.packet.src(mc.packet), mc.ctx.packet.dest(mc.packet))], [lambda : ModelForward(mc)])
  mc.popPathConstraint() # Done receive

def CacheModel(mc):
  cache = ModelMap('cached', mc, [z3.IntSort()], z3.BoolSort())
  cbody = ModelMap('cbody', mc, [z3.IntSort()], z3.IntSort())
  ModelRecv(mc)
  If(mc, cache[mc.ctx.packet.body(mc.packet)], \
        [lambda : ModelSend(mc, \
              [lambda p: mc.ctx.packet.body(p) == cbody[mc.ctx.packet.body(mc.packet)], \
               lambda p: mc.ctx.packet.src(p) == mc.ctx.packet.dest(mc.packet),\
               lambda p: mc.ctx.src_port(p) == mc.ctx.dest_port(mc.packet),\
               lambda p: mc.ctx.dest_port(p) == mc.ctx.src_port(mc.packet)])])
  mc.popPathConstraint() # Done receive
