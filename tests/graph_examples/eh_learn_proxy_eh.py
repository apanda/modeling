import networkx as nx
import mcnet.graphtools
from  mcnet.graphtools import TranslatableList, TranslatableTuple, GraphAddr, ConstructAclList
def GraphLearnFwProxy ():
    g = nx.Graph()
    fw1_policy = ConstructAclList([('a', 'c'), ('c', 'a'), ('b', 'd'), ('d', 'b')])
    g.add_node('a', factory=mcnet.graphtools.EndHostFactory(), address='a')
    g.add_node('b', factory=mcnet.graphtools.EndHostFactory(), address='b')
    g.add_node('c', factory=mcnet.graphtools.EndHostFactory(), address='c')
    g.add_node('d', factory=mcnet.graphtools.EndHostFactory(), address='d')
    g.add_node('f1', factory=mcnet.graphtools.LearningFirewallFactory(), address = 'f1', policy=fw1_policy)
    g.add_node('p', factory=mcnet.graphtools.WebProxyFactory(), address = 'p')
    g.add_edge('a', 'f1')
    g.add_edge('b', 'f1')
    g.add_edge('c', 'p')
    g.add_edge('d', 'p')
    g.add_edge('f1', 'p')
    graph = mcnet.graphtools.GraphTopo(g)
    net, ctx = graph.Network, graph.Context
    a = graph['a']
    b = graph['b']
    c = graph['c']
    d = graph['d']
    fw1 = graph['f1']
    p = graph['p']

    ip_a = graph('a')
    ip_b = graph('b')
    ip_c = graph('c')
    ip_d = graph('d')
    ip_f1 = graph('f1')
    ip_p = graph('p')
    addresses = ['a', 'b', 'c', 'd', 'f1', 'p']

    for node in [a, b]:
        net.SetGateway(node, fw1)

    for node in [c, d]:
        net.SetGateway(node, p)

    net.RoutingTable(fw1, [(ip_a, a), \
                          (ip_b, b), \
                          (ip_c, p), \
                          (ip_d, p), \
                          (ip_p, p)])

    net.RoutingTable(p, [(ip_a, fw1), \
                         (ip_b, fw1), \
                         (ip_c, c), \
                         (ip_d, d), \
                         (ip_f1, fw1)])
    #check = mcnet.components.PropertyChecker(ctx, net)
    return graph
