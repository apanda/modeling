import networkx as nx
import mcnet.graphtools
def GraphLearn2FwProxy ():
    g = nx.Graph()
    g.add_node('a', factory=mcnet.graphtools.EndHostFactory(), address='a')
    g.add_node('b', factory=mcnet.graphtools.EndHostFactory(), address='b')
    g.add_node('c', factory=mcnet.graphtools.EndHostFactory(), address='c')
    g.add_node('d', factory=mcnet.graphtools.EndHostFactory(), address='d')
    g.add_node('f1', factory=mcnet.graphtools.LearningFirewallFactory(), address = 'f1')
    g.add_node('f2', factory=mcnet.graphtools.LearningFirewallFactory(), address='f2')
    g.add_node('p', factory=mcnet.graphtools.WebProxyFactory(), address = 'p')
    g.add_edge('a', 'f1')
    g.add_edge('b', 'f1')
    g.add_edge('c', 'f2')
    g.add_edge('d', 'f2')
    g.add_edge('f1', 'p')
    g.add_edge('f2', 'p')
    graph = mcnet.graphtools.GraphTopo(g)
    net, ctx = graph.Network, graph.Context
    a = graph['a']
    b = graph['b']
    c = graph['c']
    d = graph['d']
    fw1 = graph['f1']
    fw2 = graph['f2']
    p = graph['p']

    ip_a = graph('a')
    ip_b = graph('b')
    ip_c = graph('c')
    ip_d = graph('d')
    ip_f1 = graph('f1')
    ip_f2 = graph('f2')
    ip_p = graph('p')
    addresses = ['a', 'b', 'c', 'd', 'f1', 'f2', 'p']

    for node in [a, b]:
        net.SetGateway(node,  fw1)

    for node in [c, d]:
        net.SetGateway(node, fw2)

    net.RoutingTable(fw1, [(ip_a, a), \
                          (ip_b, b), \
                          (ip_c, p), \
                          (ip_d, p), \
                          (ip_f2, p), \
                          (ip_p, p)])

    net.RoutingTable(fw2, [(ip_a, p), \
                          (ip_b, p), \
                          (ip_c, c), \
                          (ip_d, d), \
                          (ip_f1, p), \
                          (ip_p, p)])
    net.RoutingTable(p, [(ip_a, fw1), \
                         (ip_b, fw1), \
                         (ip_c, fw2), \
                         (ip_d, fw2), \
                         (ip_f1, fw1), \
                         (ip_f2, fw2)])
    #fw.AddAcls([(ip_a, ip_c), (ip_c, ip_a), (ip_b, ip_d), (ip_d, ip_b)])
    fw1.AddAcls([(ip_a, ip_c), (ip_c, ip_a), (ip_b, ip_d), (ip_d, ip_b)])
    fw2.AddAcls([(ip_a, ip_c), (ip_c, ip_a), (ip_b, ip_d), (ip_d, ip_b)])
    #check = mcnet.components.PropertyChecker(ctx, net)
    return graph
