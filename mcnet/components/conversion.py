import z3
from . import Context, NetworkObject
from collections import Iterable, defaultdict
from itertools import permutations
class VariablesAndConstraint(object):
  def __init__(self, var, constraints):
    self.variables = var
    self.constraints = constraints
  def __repr__(self):
    return '%s<<%s>>'%(str(self.constraints), ','.join(map(str, self.variables)))
  def __str__(self):
    return self.__repr__()

class ModelContext(object):
  def __init__(self, name, context, time, node):
    self.path_so_far = []
    self.vars_so_far = []
    self.implied_paths = defaultdict(lambda: [])
    self.implied_constraints = {} 
    self.iff_paths = defaultdict(lambda: [])
    self.iff_constraints = {} 
    self.time = time
    self.node = node
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
  
  def addIff(self, implication, variables = []):
    implication = VariablesAndConstraint(variables, implication)
    self.iff_constraints[str(implication)] = implication
    path_vars = dict(map(lambda k: (str(k), k), [l for s in self.vars_so_far for l in s])).values()
    self.iff_paths[str(implication)].append(VariablesAndConstraint(path_vars, list(self.path_so_far)))

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
        elif len(right.constraints) > 0:
          right_constraint.append(z3.And(right.constraints))
      if len(right_constraint) > 0:
        if len(left_vars) > 0:
          constraint = z3.ForAll(left_vars, \
                  z3.Implies(v.constraints, \
                     z3.Or(right_constraint)))
          #constraint = z3.ForAll(left_vars, \
                  #v.constraints == \
                     #z3.Or(right_constraint))
        else:
          constraint = z3.Implies(v.constraints, z3.Or(right_constraint))
          #constraint = (v.constraints == z3.Or(right_constraint))
      else:
        if len(left_vars) > 0:
          constraint = z3.ForAll(left_vars, v.constraints)
        else:
          constraint = v.constraints
      constraints.append(constraint)
    for k, v in self.iff_constraints.iteritems():
      left_vars = v.variables
      right_pairs = self.iff_paths[k]
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
        elif len(right.constraints) > 0:
          right_constraint.append(z3.And(right.constraints))
      if len(right_constraint) > 0:
        if len(left_vars) > 0:
          constraint = z3.ForAll(left_vars, \
                  v.constraints == \
                     z3.Or(right_constraint))
        else:
          constraint = (v.constraints == z3.Or(right_constraint))
      else:
        if len(left_vars) > 0:
          constraint = z3.ForAll(left_vars, v.constraints)
        else:
          constraint = v.constraints
      constraints.append(constraint)
    return constraints

def ModelSend (mcontext, packet):
  fnode = z3.Const('%s_f_n'%(mcontext.node), mcontext.ctx.node)
  pconstraint = mcontext.ctx.send(mcontext.node, \
                   fnode, \
                   packet,\
                   mcontext.time)
  mcontext.addCurrentImplication(pconstraint, [fnode, packet, mcontext.time])

def ModelRecv (mcontext, packet):
  rtime = z3.Int('%s_r_t'%(mcontext.node))
  rnode = z3.Const('%s_r_n'%(mcontext.node), mcontext.ctx.node)
  pconstraint = z3.And(mcontext.ctx.recv(rnode, 
                   mcontext.node, \
                   packet,\
                   rtime),
                rtime < mcontext.time)
  return [pconstraint, [rtime, rnode, packet]]

def DidRecv (mcontext, packet, time):
  rnode = z3.Const('%s_dr_n'%(mcontext.node), mcontext.ctx.node)
  pconstraint = mcontext.ctx.recv(rnode, mcontext.node, packet, time)
  return [pconstraint, [rnode, time, packet]]

def DidSend (mcontext, packet, time):
  rnode = z3.Const('%s_dr_n'%(mcontext.node), mcontext.ctx.node)
  pconstraint = mcontext.ctx.send(mcontext.node, rnode, packet, time)
  return [pconstraint, [rnode, time, packet]]

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
  def Set (self, key, value):
    if not isinstance(key, Iterable):
      key = [key]
    else:
      key = list(key)
    self.mcontext.addCurrentImplication(self.map_func(*key) == value)

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
  def set (self, key, value, variables = []):
    if not isinstance(key, Iterable):
      key = [key]
    else:
      key = list(key)
    #t = z3.Int('mm_t')
    key.append(self.mcontext.time)
    #self.mcontext.addPathConstraint(t >= self.mcontext.time, [t, self.mcontext.time])
    variables.append(self.mcontext.time)
    self.mcontext.addCurrentImplication(self.map_func(*key) == value, variables)
    #self.mcontext.addIff(z3.Exists([t], \
                           #z3.And(t >= self.mcontext.time, self.map_func(*key) == value)),\
                                #[self.mcontext.time])

def Body(mcontext, body):
  if not isinstance(body, Iterable):
    body = [body]
  pushed = 0
  for statement in body:
    ret = statement()
    if ret:
      if not isinstance(ret, Iterable):
        ret = [ret]
      pushed += 1
      mcontext.addPathConstraint(*ret)
  for s in xrange(pushed):
    mcontext.popPathConstraint()
  
def If(mcontext, cond, body, else_body = None):
  if not isinstance(cond, Iterable):
    mcontext.addPathConstraint(cond)
  else:
    mcontext.addPathConstraint(*cond)
  Body(mcontext, body)
  mcontext.popPathConstraint()
  if else_body:
    mcontext.addPathConstraint(z3.Not(cond))
    Body(mcontext, else_body)
    mcontext.popPathConstraint()

def AclFwModel(mc, acl):
  p = z3.Const('p', mc.ctx.packet)
  Body(mc, \
  [lambda: ModelRecv(mc, p),
   lambda: If(mc, z3.Or(\
           acl[(mc.ctx.packet.src(p), mc.ctx.packet.dest(p))], \
           acl[(mc.ctx.packet.dest(p), mc.ctx.packet.src(p))]), \
        [lambda : ModelSend(mc, p)])])

def LearningFwModel(mc, acl):
  p = z3.Const('p', mc.ctx.packet)
  #acl = ConfigMap('acl', mc, [mc.ctx.address, mc.ctx.address], z3.BoolSort())
  flows = ModelMap('flows', mc, [mc.ctx.address, mc.ctx.address, z3.IntSort(), z3.IntSort()], z3.BoolSort())
  src = z3.Const('src', mc.ctx.address)
  dest = z3.Const('dest', mc.ctx.address)
  sp = z3.Int('sp')
  dp = z3.Int('dp')
  Body(mc, \
   [lambda: ModelRecv(mc, p),
    lambda: If(mc, acl[(mc.ctx.packet.src(p), mc.ctx.packet.dest(p))], \
             [lambda: ModelSend(mc, p), \
              lambda: src == mc.ctx.packet.src(p), \
              lambda: dest == mc.ctx.packet.dest(p), \
              lambda: sp == mc.ctx.src_port(p), \
              lambda: dp == mc.ctx.dest_port(p), \
              lambda: flows.set((src, dest, sp, dp), True, [src, dest, sp, dp])], \
             [lambda: If(mc, flows[(mc.ctx.packet.dest(p), mc.ctx.packet.src(p), mc.ctx.dest_port(p), \
                                    mc.ctx.src_port(p))], \
                      [lambda: ModelSend(mc, p)])])])
def CacheModel(mc):
  cache = ModelMap('cached', mc, [z3.IntSort()], z3.BoolSort())
  cbody = ModelMap('cbody', mc, [z3.IntSort()], z3.IntSort())
  is_request = ModelMap('is_request', mc, [mc.ctx.address, z3.IntSort(), z3.IntSort()], z3.BoolSort())
  p_req = z3.Const('p_req', mc.ctx.packet)
  p_resp = z3.Const('p_resp', mc.ctx.packet)
  Body(mc, \
  [lambda: ModelRecv(mc, p_req), \
   lambda: If(mc, cache[mc.ctx.packet.body(p_req)], \
                [lambda: mc.ctx.packet.body(p_resp) == cbody[mc.ctx.packet.body(p_req)], \
                 lambda: mc.ctx.packet.src(p_resp) == mc.ctx.packet.dest(p_req), \
                 lambda: mc.ctx.src_port(p_resp) == mc.ctx.dest_port(p_req), \
                 lambda: mc.ctx.dest_port(p_resp) == mc.ctx.src_port(p_req), \
                 lambda: ModelSend(mc, p_resp)],
                 [lambda: mc.ctx.packet.body(p_resp) == mc.ctx.packet.body(p_req),
                  lambda: mc.ctx.packet.dest(p_resp) == mc.ctx.packet.dest(p_req),
                  lambda: mc.ctx.packet.dest_port(p_resp) == mc.ctx.packet.dest_port(p_req),
                  lambda: mc.ctx.packet.origin(p_resp) == mc.ctx.packet.origin(p_req),
                  lambda: mc.ctx.packet.orig_body(p_resp) == mc.ctx.packet.orig_body(p_req),
                  lambda: mc.ctx.nodeHasAddr(mc.ctx.packet.src(p_resp), mc.node),
                  lambda: ModelSend(mc, p_resp)])])
class ConvertedAclFw (NetworkObject):
  def _init(self, node, network, context):
    self.fw = node.z3Node
    self.ctx = context
    self.constraints = list ()
    self.acls = list ()
    network.SaneSend (self)

  @property
  def z3Node (self):
    return self.fw

  def AddAcls(self, acls):
    if not isinstance(acls, list):
      acls = [acls]
    self.acls.extend(acls)

  @property
  def ACLs(self):
    return self.acls

  def _addConstraints(self, solver):
    mc = ModelContext('%s'%(self.fw), self.ctx, z3.Int('%s_t'%(self.fw)), self.fw)
    acls = ConfigMap('%s_acl'%(self.fw), mc, [self.ctx.address, self.ctx.address], z3.BoolSort())
    AclFwModel(mc, acls)
    addr_pairs = list(permutations(self.ctx.address_list, 2))
    acl_as_text = map(lambda (a, b): '%s:%s'%(a, b), self.acls)
    for (a, b) in addr_pairs:
      pair_as_text = '%s:%s'%(a, b)
      if pair_as_text not in acl_as_text:
        acls.Set([a, b], False)
      else:
        acls.Set([a, b], True)
    solver.add(mc.getAllConstraints())

class ConvertedLearningFw (NetworkObject):
  def _init(self, node, network, context):
    self.fw = node.z3Node
    self.ctx = context
    self.constraints = list ()
    self.acls = list ()
    network.SaneSend (self)

  @property
  def z3Node (self):
    return self.fw

  def AddAcls(self, acls):
    if not isinstance(acls, list):
      acls = [acls]
    self.acls.extend(acls)

  @property
  def ACLs(self):
    return self.acls

  def _addConstraints(self, solver):
    mc = ModelContext('%s'%(self.fw), self.ctx, z3.Int('%s_t'%(self.fw)), self.fw)
    acls = ConfigMap('%s_acl'%(self.fw), mc, [self.ctx.address, self.ctx.address], z3.BoolSort())
    LearningFwModel(mc, acls)
    addr_pairs = list(permutations(self.ctx.address_list, 2))
    acl_as_text = map(lambda (a, b): '%s:%s'%(a, b), self.acls)
    for (a, b) in addr_pairs:
      pair_as_text = '%s:%s'%(a, b)
      if pair_as_text not in acl_as_text:
        acls.Set([a, b], False)
      else:
        acls.Set([a, b], True)
    solver.add(mc.getAllConstraints())
