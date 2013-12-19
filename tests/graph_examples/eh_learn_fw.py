import networkx as nx
import mcnet.graphtools
from  mcnet.graphtools import TranslatableList, TranslatableTuple, GraphAddr, ConstructAclList
def GraphLearnFwNoProxy ():
    g = nx.DiGraph()
    fw1_policy = ConstructAclList([('ac0', 'cc0'), ('cc0', 'ac0'), ('bc0', 'dc0'), ('dc0', 'bc0')]) 
    g.add_node('a', factory=mcnet.graphtools.EndHostFactory(), address='ac0', gateway='f')
    g.add_node('b', factory=mcnet.graphtools.EndHostFactory(), address='bc0', gateway='f')
    g.add_node('c', factory=mcnet.graphtools.EndHostFactory(), address='cc0', gateway='f')
    g.add_node('d', factory=mcnet.graphtools.EndHostFactory(), address='dc0', gateway='f')
    g.add_node('f', factory=mcnet.graphtools.LearningFirewallFactory(), address='fc0', policy=fw1_policy)
    g.add_edge('a', 'f')
    g.add_edge('b', 'f')
    g.add_edge('c', 'f')
    g.add_edge('d', 'f')
    graph = mcnet.graphtools.GraphTopo(g)
    net, ctx = graph.Network, graph.Context
    a = graph['a']
    b = graph['b']
    c = graph['c']
    d = graph['d']
    fw = graph['f']

    ip_a = graph('ac0')
    ip_b = graph('bc0')
    ip_c = graph('cc0')
    ip_d = graph('dc0')
    ip_f = graph('fc0')
    addresses = ['ac0', 'bc0', 'cc0', 'dc0', 'fc0']

    net.RoutingTable(fw, [(ip_a, a), \
                          (ip_b, b), \
                          (ip_c, c), \
                          (ip_d, d)])
    #fw.AddAcls([(ip_a, ip_c), (ip_c, ip_a), (ip_b, ip_d), (ip_d, ip_b)])
    #check = mcnet.components.PropertyChecker(ctx, net)
    return graph
