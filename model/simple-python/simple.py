"""
A simplish model for a network.
This is in Python since OCaml wasn't working
"""
import z3
packet = z3.Datatype('Packet')
address = z3.DeclareSort('Address')
endhost, (a, b, c, d, fw_eh) = z3.EnumSort('Endhost', ['a', 'b', 'c', 'd', 'fw_eh'])
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
                                     z3.Exists([eh3], send(packet.origin(p), eh3, p)))))
    #base_conditions.append(z3.ForAll([eh1,eh3, eh4, p], z3.Implies((eh1 == packet.origin(p)) and\
    #                         recv(eh3, eh4, p),
    #                        z3.Exists([eh2], send(eh1, eh2, p))))) 
    return base_conditions

def FirewallDenyRules (solver, fw, hosts, rules):
    p = z3.Const('p', packet)
    eh = z3.Const('temp_eh', endhost)

    # Coerce all host traffic through a firewall
    for host in hosts:
        solver.add(z3.ForAll([eh, p], z3.Implies(send(host, eh, p),\
                                    eh == fw)))
    if len(rules) == 0:
        return
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

def WebProxyRules (solver, proxy, hosts):
    p = z3.Const('p', packet)
    eh = z3.Const('temp_eh', endhost)
    # This is just about connectivity
    for host in hosts:
        solver.add(z3.ForAll([eh, p], z3.Implies(send(host, eh, p),\
                                    eh == proxy)))
    
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
for h in [a,b,c,d]:
    solver.add(z3.ForAll([eh, p], z3.Implies(recv(eh, h, p), address_in_host(h, packet.dest(p)))))
    solver.add(z3.ForAll([eh, p], z3.Implies(send(h, eh, p), address_in_host(h, packet.src(p)))))
FirewallDenyRules(solver, fw_eh, [a, b, c, d], [(ada, adb), (adc, add)])
solver.add(z3.Exists([eh], recv(eh, b, p)))
solver.add(packet.origin(p) == c)
p2 = z3.Const('p2', packet)
solver.add(z3.Exists([eh], recv(eh, c, p2)))
solver.add(packet.origin(p2) == b)
print solver
print "===================================================================================="
result = solver.check ()
print result
if result == z3.sat:
    model = solver.model()
    print model
elif result == z3.unknown:
    print z3.reason_unknown()
