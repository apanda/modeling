import z3
ep = z3.DeclareSort('Endpoint')
vara = z3.Const('a', ep)
varb = z3.Const('b', ep)
f = z3.Function('f', ep, ep)
s = z3.Solver ()
s.add(vara != varb, f(vara) == varb, f(f(vara)) == vara)
print (s.check())
print (s.model())
