"""
A simplish model for a network.
This is in Python since OCaml wasn't working
"""
import z3
packet = z3.Datatype('Packet')
address = z3.DeclareSort('Address')
endhost, (a, b, c, d, fw_eh, proxy) = z3.EnumSort('Endhost', ['a', 'b', 'c', 'd', 'fw_eh', 'proxy'])
packet.declare('packet', ('src', address), ('dest', address), ('origin', endhost))
packet = packet.create()
address_in_host = z3.Function('hostHasAddr', endhost, address, z3.BoolSort ())
address_to_host = z3.Function('addrToHost', address, endhost)
z3.set_param('produce-proof', True)
# send := src -> dst -> packet -> bool
send = z3.Function('send', endhost, endhost, packet, z3.BoolSort ())
# recv := src -> dst -> packet ->bool
recv = z3.Function('recv', endhost, endhost, packet, z3.BoolSort ())
def GetBaseConditions ():
    eh1 = z3.Const('eh1', endhost)
    eh2 = z3.Const('eh2', endhost)
    eh3 = z3.Const('eh3', endhost)
    eh4 = z3.Const('eh4', endhost)
    ad1 = z3.Const('ad1', address)
    p = z3.Const('p', packet)
    base_conditions = []
    # Symmetry
    base_conditions.append(z3.ForAll([eh1, ad1], address_in_host(eh1, ad1) == (address_to_host(ad1) == eh1)))
    # All hosts are addressable
    base_conditions.append(z3.ForAll([eh1], z3.Exists([ad1], address_in_host(eh1, ad1))))
    
    # All sent packets are received
    base_conditions.append (z3.ForAll([eh1, eh2, p], recv(eh1, eh2, p) ==  send(eh1, eh2, p)))
    
    # All received packets were once sent (don't invent packets).
    base_conditions.append(z3.ForAll([eh1, eh2, p], z3.Implies(recv(eh1, eh2, p),
                                     z3.Exists([eh3], send(address_to_host(packet.src(p)), eh3, p)))))
    # Turn off loopback, loopback makes me sad
    base_conditions.append(z3.ForAll([eh1, eh2, p], z3.Implies(send(eh1, eh2, p), eh1 != eh2)))
    base_conditions.append(z3.ForAll([eh1, eh2, p], z3.Implies(recv(eh1, eh2, p), eh1 != eh2)))
    #base_conditions.append(z3.ForAll([eh1,eh3, eh4, p], z3.Implies((eh1 == packet.origin(p)) and\
    #                         recv(eh3, eh4, p),
    #                        z3.Exists([eh2], send(eh1, eh2, p))))) 
    return base_conditions

def FirewallDenyRules (solver, fw, adj, rules):
    p = z3.Const('p', packet)
    eh = z3.Const('temp_eh', endhost)
    eh2 = z3.Const('temp_eh2', endhost)
    solver.add(z3.ForAll([eh, p], z3.Implies(send(fw, eh, p), z3.Exists([eh2], recv(eh2, fw, p)))))
    adjacency_constraint = z3.Or(map(lambda n: eh == n, adj))
    # This is just about connectivity
    solver.add(z3.ForAll([eh, p], z3.Implies(recv(eh, fw, p),\
                            adjacency_constraint)))
    solver.add(z3.ForAll([eh, p], z3.Implies(send(fw, eh, p),\
                            adjacency_constraint)))

    if len(rules) == 0:
        return
    # The firewall never invents packets
    conditions = []

    # Firewall rules
    for rule in rules:
        (ada, adb) = rule
        conditions.append(z3.And(packet.src(p) == ada,
                                    packet.dest(p) == adb))
        conditions.append(z3.And(packet.src(p) == adb,
                                    packet.dest(p) == ada))
    # Actually enforce firewall rules
    solver.add(z3.ForAll([eh, p], z3.Implies(send(fw, eh, p),
                z3.Not(z3.Or(conditions)))))

def WebProxyRules (solver, proxy, adj):
    p = z3.Const('p', packet)
    p2 = z3.Const('p2', packet)
    eh = z3.Const('temp_eh', endhost)
    eh2 = z3.Const('temp_eh2', endhost)
    adjacency_constraint = z3.Or(map(lambda n: eh == n, adj))
    # This is just about connectivity
    solver.add(z3.ForAll([eh, p], z3.Implies(recv(eh, proxy, p),\
                            adjacency_constraint)))
    solver.add(z3.ForAll([eh, p], z3.Implies(send(proxy, eh, p),\
                            adjacency_constraint)))
    solver.add(z3.ForAll([eh, p], z3.Implies(send(proxy, eh, p), address_in_host(proxy, packet.src(p)))))
    solver.add(z3.ForAll([eh, p], z3.Implies(send(proxy, eh, p), z3.Exists([p2, eh2], 
                         z3.And(recv(eh2, proxy, p2),
                             z3.And(packet.origin(p2) == packet.origin(p),
                                    packet.dest(p2) == packet.dest(p)))))))


def EndHostRules (solver, hosts, adj):
    eh = z3.Const('eh', endhost)
    adjacency_constraint = z3.Or(map(lambda n: eh == n, adj))
    for h in hosts:
        solver.add(z3.ForAll([eh, p], z3.Implies(recv(eh, h, p), address_in_host(h, packet.dest(p)))))
        solver.add(z3.ForAll([eh, p], z3.Implies(send(h, eh, p), address_in_host(h, packet.src(p)))))
        solver.add(z3.ForAll([eh, p], z3.Implies(send(h, eh, p), packet.origin(p) == h)))
        solver.add(z3.ForAll([eh, p], z3.Implies(recv(eh, h, p),\
                                    adjacency_constraint)))
        solver.add(z3.ForAll([eh, p], z3.Implies(send(h, eh, p),\
                                    adjacency_constraint)))

solver = z3.Solver()
base_conditions = GetBaseConditions ()
for i in xrange(0, len(base_conditions)):
    solver.add(base_conditions[i])
ada = z3.Const('addr_a', address)
adb = z3.Const('addr_b', address)
adc = z3.Const('addr_c', address)
add = z3.Const('addr_d', address)
eh = z3.Const('eh', endhost)
solver.add(address_to_host(ada) == a)
solver.add(address_to_host(adb) == b)
addr = z3.Const('free_addr', address)
solver.add(z3.ForAll([addr], address_in_host(a, addr) == (addr == ada)))
solver.add(z3.ForAll([addr], address_in_host(b, addr) == (addr == adb)))
solver.add(z3.ForAll([addr], address_in_host(c, addr) == (addr == adc)))
solver.add(z3.ForAll([addr], address_in_host(d, addr) == (addr == add)))
p = z3.Const('p', packet)

EndHostRules(solver, [a,b], [proxy])
EndHostRules(solver, [c,d], [fw_eh])

#FirewallDenyRules(solver, fw_eh, [c,d,proxy], [(ada, adc), (adb, add)])
#WebProxyRules(solver, proxy, [a,b,fw_eh])
FirewallDenyRules(solver, fw_eh, [a, b, proxy], [(ada, adc), (adb, add)])
WebProxyRules(solver, proxy, [c, d, fw_eh])

solver.add(z3.Exists([eh], recv(eh, c, p)))
solver.add(packet.origin(p) == a)
p2 = z3.Const('p2', packet)
solver.add(z3.Exists([eh], recv(eh, d, p2)))
solver.add(packet.origin(p2) == b)
print solver
print "===================================================================================="
result = solver.check ()
print result
if result == z3.sat:
    model = solver.model()
    print model.sexpr()

