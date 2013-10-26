"""
A simplish model for a network.
This is in Python since OCaml wasn't working
"""
import z3
packet = z3.Datatype('Packet')
address = z3.DeclareSort('Address')
endhost = z3.DeclareSort('Endhost')
packet.declare('packet', ('src', address), ('dest', address), ('origin', endhost))
packet = packet.create()
address_in_host = z3.Function('hostHasAddr', endhost, address, z3.BoolSort ())
address_to_host = z3.Function('addrToHost', address, endhost)
eh1 = z3.Const('eh1', endhost)
eh2 = z3.Const('eh2', endhost)
ad1 = z3.Const('ad1', address)
p = z3.Const('p', packet)
base_conditions = []
# Symmetry
base_conditions.append(z3.ForAll([eh1, ad1], address_in_host(eh1, ad1) == (address_to_host(ad1) == eh1)))
# All hosts are addressable
base_conditions.append(z3.ForAll([eh1], z3.Exists([ad1], address_in_host(eh1, ad1))))

send = z3.Function('send', endhost, endhost, packet, z3.BoolSort ())
recv = z3.Function('recv', endhost, endhost, packet, z3.BoolSort ())

# All sent packets are received, only packets received are ones which were sent
base_conditions.append (z3.ForAll([eh1, eh2, p], recv(eh1, eh2, p) ==  send(eh2, eh1, p)))
base_conditions.append(z3.ForAll([eh1, p], z3.Implies(eh1 == packet.origin(p), z3.Exists([eh2], send(eh1, eh2, p))))) 
solver = z3.Solver()
print (solver.check ())
