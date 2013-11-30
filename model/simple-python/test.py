# IPython log file

get_ipython().magic(u'logstart test,py')
import components
context = components.Context(['a', 'b', 'c', 'd', 'w', 'f1', 'f2'], ['ada', 'adb', 'adc', 'add', 'adw', 'adf1', 'adf2'])
network = components.Network('net', context)
a = components.EndHost(context.a, context)
b = components.EndHost(context.b, context)
c = components.EndHost(context.c, context)
d = components.EndHost(context.d, context)
w = components.WebProxy(context.w, network, context)
f1 = components.LearningFirewall(context.f1, network, context)
f2 = components.LearningFirewall(context.f2, network, context)
network.AdjacencyMap([(a, [f1]), (b, [f1]), (c, [f2]), (w, [f1, f2]), (f1, [a, b, w]), (f2, [c, d, w])])
network.setAddressMappings([(a, context.ada), \
                            (b, context.adb), \
                            (c, context.adc), \
                            (d, context.add), \
                            (w, context.adw), \
                            (f1, context.adf1), \
                            (f2, context.adf2)])
network.RoutingTable(a, [(x, f1) for x in [context.adb, context.adc, context.add, context.adw, context.adf1, context.adf2]])
network.RoutingTable(b, [(x, f1) for x in [context.ada, context.adc, context.add, context.adw, context.adf1, context.adf2]])
network.RoutingTable(c, [(x, f2) for x in [context.ada, context.adb, context.add, context.adw, context.adf1, context.adf2]])
network.RoutingTable(d, [(x, f2) for x in [context.ada, context.adb, context.adc, context.adw, context.adf1, context.adf2]])
network.RoutingTable(w, [(context.ada, f1), (context.adb, f1), (context.adc, f2), (context.add, f2), (context.adf1, f1), (context.adf2, f2)])
network.RoutingTable(f1, [(context.ada, a), (context.adb, b), (context.adc, w), (context.add, w), (context.adw, w), (context.adf2, w)])
network.RoutingTable(f2, [(context.ada, w), (context.adb, w), (context.adc, c), (context.add, d), (context.adw, w), (context.adf1, w)])
f1.AddAcls([(context.ada, context.adc), (context.adc, context.ada)])
f2.AddAcls([(context.ada, context.adc), (context.adc, context.ada)])
network.Attach(a,b,c,d,w, f1, f2)
checker = components.PropertyChecker(context, network)
checker.AddIsolationProperty(a, c)
get_ipython().magic(u'logoff')
