# IPython log file

get_ipython().magic(u'logstart test,py')
import components
context = components.Context(['a', 'b', 'c', 'd', 'w', 'f'], ['ada', 'adb', 'adc', 'add', 'adw', 'adf'])
network = components.Network('net', context)
a = components.EndHost(context.a, context)
b = components.EndHost(context.b, context)
c = components.EndHost(context.c, context)
d = components.EndHost(context.d, context)
w = components.WebProxy(context.w, network, context)
f = components.LearningFirewall(context.f, network, context)
network.AdjacencyMap([(a, [f]), (b, [f]), (c, [w]), (w, [f, c, d]), (f, [a, b, w])])
network.setAddressMappings([(a, context.ada), \
                            (b, context.adb), \
                            (c, context.adc), \
                            (d, context.add), \
                            (w, context.adw), \
                            (f, context.adf)])
network.RoutingTable(a, [(x, f) for x in [context.adb, context.adc, context.add, context.adw, context.adf]])
network.RoutingTable(b, [(x, f) for x in [context.ada, context.adc, context.add, context.adw, context.adf]])
network.RoutingTable(c, [(x, w) for x in [context.ada, context.adb, context.add, context.adw, context.adf]])
network.RoutingTable(d, [(x, w) for x in [context.ada, context.adb, context.adc, context.adw, context.adf]])
network.RoutingTable(w, [(context.ada, f), (context.adb, f), (context.adc, c), (context.add, d), (context.adf, f)])
network.RoutingTable(f, [(context.ada, a), (context.adb, b), (context.adc, w), (context.add, w), (context.adw, w)])
f.AddAcls([(context.ada, context.adc), (context.adc, context.ada)])
network.Attach(a,b,c,d,w, f)
checker = components.PropertyChecker(context, network)
checker.AddIsolationProperty(a, c)
checker.CheckNow()
get_ipython().magic(u'logoff')
