import networkx as nx
import mcnet.graphtools
def GraphAclFwNoProxy ():
    g = nx.Graph()
    g.add_node('a', factory=mcnet.graphtools.EndHostFactory(), address='ac0')
    g.add_node('b', factory=mcnet.graphtools.EndHostFactory(), address='bc0')
    g.add_node('c', factory=mcnet.graphtools.EndHostFactory(), address='cc0')
    g.add_node('d', factory=mcnet.graphtools.EndHostFactory(), address='dc0')
    g.add_node('f', factory=mcnet.graphtools.AclFirewallFactory(), address='fc0')
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

    for node in net.EndHosts.itervalues():
        net.RoutingTable(node, [(graph(x), fw) for x in addresses])

    net.RoutingTable(fw, [(ip_a, a), \
                          (ip_b, b), \
                          (ip_c, c), \
                          (ip_d, d)])
    #fw.AddAcls([(ip_a, ip_c), (ip_c, ip_a), (ip_b, ip_d), (ip_d, ip_b)])
    fw.AddAcls([(ip_a, ip_c), (ip_b, ip_d)])
    #check = mcnet.components.PropertyChecker(ctx, net)
    return graph
