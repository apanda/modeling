# coding=utf-8
import z3
nodes = ['a', 'b', 'f1', 'f2']
addresses = ['ip_a', 'ip_b', 'ip_f1', 'ip_f2']
# Nodes in a network
node, node_list = z3.EnumSort('Node', nodes)
nodes = dict(zip(nodes, node_list))

# Addresses for this network
address, address_list = z3.EnumSort('Address', addresses)
addresses = dict(zip(addresses, address_list))

a = nodes['a']
b = nodes['b']
f1 = nodes['f1']
f2 = nodes['f2']
ip_a = addresses['ip_a']
ip_b = addresses['ip_b']
ip_f1 = addresses['ip_f1']
ip_f2 = addresses['ip_f2']

packet = z3.DeclareSort('packets')
port = z3.DeclareSort('ports')
body = z3.DeclareSort('body')
time = z3.IntSort()
event = z3.DeclareSort('event')

#src : E -> N
#dst : E -> N
#p : E -> P
#t : E -> T

src = z3.Function('src', event, node)
dst = z3.Function('dst', event, node)
p = z3.Function('p', event, packet)
t = z3.Function('t', event, time)

#src_P : E -> IP
#dst_P : E -> IP
src_P = z3.Function('src_p', event, address)
dst_P = z3.Function('dst_p', event, address)

#sport : E -> Po
#dport : E -> Po
#addrToNode : IP -> N
sport = z3.Function('sport', event, port)
dport = z3.Function('dport', event, port)
addrToNode = z3.Function('addrToNode', address, node)

#origin : E -> N
#body : E -> B
origin = z3.Function('origin', event, node)
body = z3.Function('body', event, body)

#cause : E -> E
cause = z3.Function('cause', event, event)
#f1_cause : E -> E
f1_cause = z3.Function('f1_cause', event, event)
#f2_cause: E -> E
f2_cause = z3.Function('f2_cause', event, event)


#snd : E
#rcv : E
#< : T * T [Implicit]
#nodeHasAddr : N * IP
#f1_acl_func : IP * IP
#f2_acl_func : IP * IP
snd = z3.Function('snd', event, z3.BoolSort())
rcv = z3.Function('rcv', event, z3.BoolSort())
nodeHasAddr = z3.Function('nodeHasAddr', node, address, z3.BoolSort())
f1_acl_func = z3.Function('f1_acl_func', address, address, z3.BoolSort())
f2_acl_func = z3.Function('f2_acl_func', address, address, z3.BoolSort())

assertions = []

# Extra axioms:
# =============
# ∀ e:E. snd(e) <-> ~ rcv(e)
# 
# axioms for < : linear strict order on T with 0 as minimum
# 
# ∀ e1:E,e2:E. p(e1) = p(e2) ⇒ body(e1) = body(e2)    (body is a function of the packet)
# ∀ e1:E,e2:E. p(e1) = p(e2) ⇒ dport(e1) = dport(e2)    (dport is a function of the packet)
# ∀ e1:E,e2:E. p(e1) = p(e2) ⇒ sport(e1) = sport(e2)    (sport is a function of the packet)
# ∀ e1:E,e2:E. p(e1) = p(e2) ⇒ origin(e1) = origin(e2)    (origin is a function of the packet)
# ∀ e1:E,e2:E. p(e1) = p(e2) ⇒ src_P(e1) = src_P(e2)    (src_P is a function of the packet)
# ∀ e1:E,e2:E. p(e1) = p(e2) ⇒ dst_P(e1) = dst_P(e2)    (dst_P is a function of the packet)
# 
# 
# 
# ∀ e:E. snd(e) ⇒ cause(e) = e   (there is no cause for snd events)
# 
# ∀ e:E. rcv(e) ⇒ f1_cause(e) = e   (there is no f_cause for rcv events)
# ∀ e:E. snd(e) ∧ src(e) ≠ f1 ⇒ f1_cause(e) = e   (there is no f_cause for snd events whose src is not f)
# 
# ∀ e:E. rcv(e) ⇒ f2_cause(e) = e   (there is no f_cause for rcv events)
# ∀ e:E. snd(e) ∧ src(e) ≠ f2 ⇒ f2_cause(e) = e   (there is no f_cause for snd events whose src is not f)
e1 = z3.Const('e1', event)
e2 = z3.Const('e2', event)
e3 = z3.Const('e3', event)
assertions.append(z3.ForAll([e1], snd(e1) == z3.Not(rcv(e1))))
assertions.append(z3.ForAll([e1], t(e1) >= 0))
assertions.append(z3.ForAll([e1, e2], z3.Implies(p(e1) == p(e2), body(e1) == body(e2))))
assertions.append(z3.ForAll([e1, e2], z3.Implies(p(e1) == p(e2), dport(e1) == dport(e2))))
assertions.append(z3.ForAll([e1, e2], z3.Implies(p(e1) == p(e2), sport(e1) == sport(e2))))
assertions.append(z3.ForAll([e1, e2], z3.Implies(p(e1) == p(e2), origin(e1) == origin(e2))))
assertions.append(z3.ForAll([e1, e2], z3.Implies(p(e1) == p(e2), src_P(e1) == src_P(e2))))
assertions.append(z3.ForAll([e1, e2], z3.Implies(p(e1) == p(e2), dst_P(e1) == dst_P(e2))))
assertions.append(z3.ForAll([e1], z3.Implies(snd(e1), cause(e1) == e1)))
assertions.append(z3.ForAll([e1], z3.Implies(rcv(e1), f1_cause(e1) == e1)))
assertions.append(z3.ForAll([e1], z3.Implies(z3.And(snd(e1), src(e1) != f1), f1_cause(e1) == e1)))
assertions.append(z3.ForAll([e1], z3.Implies(rcv(e1), f2_cause(e1) == e1)))
assertions.append(z3.ForAll([e1], z3.Implies(z3.And(snd(e1), src(e1) != f2), f2_cause(e1) == e1)))

#NEW: ∀ e:E. src(e) ≠ dst(e)
#
#NEW: ∀ e:E. src_P(e) ≠ dst_P(e)
#
# NEW: ∀ e:E. rcv(e) ⇒ t(cause(e)) < t(e) ∧ snd(cause(e)) ∧ src(cause(e)) = src(e) ∧ dst(cause(e)) = dst(e) ∧ p(e) = p(cause(e))
assertions.append(z3.ForAll([e1], src(e1) != dst(e1)))
assertions.append(z3.ForAll([e1], src_P(e1) != dst_P(e1)))
assertions.append(z3.ForAll([e1], z3.Implies(rcv(e1), \
                       z3.And([t(cause(e1)) < t(e1), \
                               snd(cause(e1)), \
                               src(cause(e1)) == src(e1), \
                               dst(cause(e1)) == dst(e1), \
                               p(cause(e1)) == p(e1)]))))

# NEW: ∀ e:E. snd(e) ∧ src(e) = f ⇒ ¬nodeHasAddr(f, dst_P(e)) 
assertions.append(z3.ForAll([e1], z3.Implies(z3.And(snd(e1), src(e1) == f1), z3.Not(nodeHasAddr(f1, dst_P(e1))))))
assertions.append(z3.ForAll([e1], z3.Implies(z3.And(snd(e1), src(e1) == f2), z3.Not(nodeHasAddr(f2, dst_P(e1))))))

ip1 = z3.Const('ip1', address)
ip2 = z3.Const('ip2', address)
ip3 = z3.Const('ip3', address)
#NEW: addrToNode(ip_a) = a 
#∀ ip:IP. ip = ip_a <-> nodeHasAddr(a, ip_a) 
assertions.append(nodeHasAddr(a, ip_a))
assertions.append(nodeHasAddr(b, ip_b))
assertions.append(nodeHasAddr(f1, ip_f1))
assertions.append(nodeHasAddr(f2, ip_f2))


#NEW: ∀ e:E. snd(e) ∧ src(e) = a ⇒ nodeHasAddr(a, src_P(e)) 
#...and so on for b,c,d,cc...
#NEW: ∀ e:E. snd(e) ∧ src(e) = a ⇒ origin(e) = a
#...and so on for b,c,d...
assertions.append(z3.ForAll([e1], \
        z3.Implies(z3.And(snd(e1), src(e1) == a), \
            z3.And(nodeHasAddr(a, src_P(e1)), \
                    origin(e1) == a))))

assertions.append(z3.ForAll([e1], \
        z3.Implies(z3.And(snd(e1), src(e1) == b), \
            z3.And([nodeHasAddr(b, src_P(e1)), \
                    origin(e1) == b]))))

assertions.append(z3.ForAll([e1], \
        z3.Implies(z3.And(rcv(e1), dst(e1) == a), \
            z3.And([nodeHasAddr(a, dst_P(e1))]))))

assertions.append(z3.ForAll([e1], \
        z3.Implies(z3.And(rcv(e1), dst(e1) == b), \
            z3.And([nodeHasAddr(b, dst_P(e1))]))))

# NEW: ∀ e:E. snd(e) ∧ src(e) = a ∧ (dst_P(e) = ip_a ∨ dst_P(e) = ip_b ∨ dst_P(e) = ip_c ∨ dst_P(e) = ip_d ∨ dst_P(e) = ip_f ∨ dst_P(e) = ip_cc) ⇒ dst(e) = f 
# ...and so on for b,c,d...
# Composition
assertions.append(z3.ForAll([e1], \
        z3.Implies(z3.And(snd(e1), src(e1) == a), dst(e1) == f1)))
assertions.append(z3.ForAll([e1], \
        z3.Implies(z3.And(snd(e1), src(e1) == b), dst(e1) == f1)))
assertions.append(z3.ForAll([e1], \
        z3.Implies(z3.And(snd(e1), src(e1) == f1), dst(e1) == f2)))
assertions.append(z3.ForAll([e1], \
        z3.Implies(z3.And(snd(e1), src(e1) == f2), dst(e1) == f1)))
#assertions.append(z3.ForAll([e1], \
        #z3.Implies(z3.And(snd(e1), src(e1) == f2, dst_P(e1) == ip_a), dst(e1) == a)))
#assertions.append(z3.ForAll([e1], \
        #z3.Implies(z3.And(snd(e1), src(e1) == f2, dst_P(e1) == ip_b), dst(e1) == b)))
#assertions.append(z3.ForAll([e1], \
        #z3.Implies(z3.And(snd(e1), src(e1) == f2, dst_P(e1) == ip_f1), dst(e1) == f1)))

# NEW: ∀ ip1:IP, ip2:IP. f_acl_func(ip1, ip2) <-> ¬(ip1 = ip_a ∧ ip2 = ip_b ∨ ip1 = ip_b ∧ ip2 = ip_a ∨ ip1 = ip_c ∧ ip2 = ip_d ∨ ip1 = ip_d ∧ ip2 = ip_c) 
assertions.append(z3.ForAll([ip1, ip2], f1_acl_func(ip1, ip2)))
assertions.append(z3.ForAll([ip1, ip2], f2_acl_func(ip1, ip2)))


# NEW: ∀ e:E. snd(e) ∧ src(e) = f ⇒ f_acl_func(src_P(e), dst_P(e)) 
#	 ∀ e:E. snd(e) ∧ src(e) = f ⇒ t(f_cause(e)) < t(e) ∧ rcv(f_cause(e)) ∧ dst(f_cause(e)) = f ∧ p(f_cause(e)) = p(e)
assertions.append(z3.ForAll([e1], z3.Implies(z3.And(snd(e1), src(e1) == f1), f1_acl_func(src_P(e1), dst_P(e1)))))
assertions.append(z3.ForAll([e1], z3.Implies(z3.And(snd(e1), src(e1) == f1), \
                    z3.And(t(f1_cause(e1)) < t(e1), \
                           rcv(f1_cause(e1)), \
                           dst(f1_cause(e1)) == f1, \
                           p(f1_cause(e1)) == p(e1)))))

assertions.append(z3.ForAll([e1], z3.Implies(z3.And(snd(e1), src(e1) == f2), f2_acl_func(src_P(e1), dst_P(e1)))))
assertions.append(z3.ForAll([e1], z3.Implies(z3.And(snd(e1), src(e1) == f2), \
                    z3.And(t(f2_cause(e1)) < t(e1), \
                           rcv(f2_cause(e1)), \
                           dst(f2_cause(e1)) == f2, \
                           p(f2_cause(e1)) == p(e1)))))
solver = z3.Solver()
solver.add(assertions)
def CheckInvariant (inv):
  solver.push()
  solver.add(inv)
  r = solver.check()
  model = None
  if r == z3.sat:
    model = solver.model()
  solver.pop()
  return (r, model)
e = e2
print "Sanity checks"
print "%s should be unsat"%(CheckInvariant(cause(cause(e2)) != cause(e2))[0])
print "%s should be unsat"%(CheckInvariant(f1_cause(f1_cause(e)) != f1_cause(e))[0])
print "%s should be unsat"%(CheckInvariant(z3.And(f1_cause(cause(f1_cause(e2))) != f1_cause(cause(e2)),\
    f1_cause(cause(f1_cause(e2))) != cause(f1_cause(e2))))[0])
print "%s should be sat"%(CheckInvariant(z3.And(f1_cause(cause(f1_cause(e2))) != f1_cause(cause(e2))))[0])
print "%s should be unsat"%(CheckInvariant(z3.And(f1_cause(f2_cause(e)) != f1_cause(e), f1_cause(f2_cause(e)) !=
    f2_cause(e)))[0])
print "%s should be unsat"%(CheckInvariant(z3.And(f2_cause(f1_cause(e)) != f1_cause(e), f2_cause(f1_cause(e)) !=
    f2_cause(e)))[0])
print "%s should be unsat"%(CheckInvariant(z3.And(f1_cause(e) != e, f2_cause(e) != e))[0])
interesting = cause(f1_cause(cause(f2_cause(e)))) != cause(cause(f1_cause(cause(f2_cause(e)))))
print '%s should be unsat'%(CheckInvariant(interesting)[0])
interesting2 = (f2_cause(cause(f1_cause(cause(f2_cause(e))))) != cause(f1_cause(cause(f2_cause(e)))))
interesting3 = (f1_cause(cause(f2_cause(cause(f1_cause(cause(f2_cause(e))))))) != cause(f2_cause(cause(f1_cause(cause(f2_cause(e)))))))
interesting4 = (f2_cause(cause(f1_cause(cause(f2_cause(cause(f1_cause(cause(f2_cause(e))))))))) !=
        cause(f1_cause(cause(f2_cause(cause(f1_cause(cause(f2_cause(e)))))))))
print 'When no loop %s should be unsat (else SAT)'%(CheckInvariant(interesting4)[0])
def PrintInfo(m, e):
    print 'src: %s'%(m.eval(src(e)))
    print 'dst: %s'%(m.eval(dst(e)))
    print 'snd: %s'%(m.eval(snd(e)))
    print 'rcv: %s'%(m.eval(rcv(e)))
    print 'src_P: %s'%(m.eval(src_P(e)))
    print 'dst_P: %s'%(m.eval(dst_P(e)))
    print 't: %s'%(m.eval(t(e)))

