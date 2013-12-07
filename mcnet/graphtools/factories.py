from components import LoadBalancer, \
                       EndHost, \
                       AclFirewall, \
                       LearningFirewall, \
                       WebProxy
""" Some factories for instantiating elements in a nicer way"""
def LoadBalancerFactory (saddr, servers):
    def InitLoadBalancer (graph, lb):
        servers = map(lambda s: graph[s], servers)
        lb.AddServers (servers)
    def CreateLoadBalancer (graph, node):
        lb = LoadBalancer(node, saddr, None, graph.Context)
        graph.AddNodeInitializer (InitLoadBalancer, [graph, lb]) 
        return lb
    return CreateLoadBalancer

def EndHostFactory ():
    def CreateEndHost (graph, node):
        return EndHost(node, graph.Network, graph.Context) 
    return CreateEndHost

def AclFirewallFactory ():
    def CreateAclFirewall (graph, node):
        return AclFirewall(node, graph.Network, graph.Context) 
    return CreateAclFirewall

def LearningFirewallFactory ():
    def CreateLearningFirewall (graph, node):
        return LearningFirewall(node, graph.Network, graph.Context) 
    return CreateLearningFirewall

def WebProxyFactory ():
    def CreateWebProxy (graph, node):
        return WebProxy(node, graph.Network, graph.Context) 
    return CreateWebProxy
