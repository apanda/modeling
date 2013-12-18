from components import LoadBalancer, \
                       EndHost, \
                       AclFirewall, \
                       LearningFirewall, \
                       WebProxy, \
                       IPS, \
                       WANOptTransformer
""" 
Some factories for instantiating elements in a nicer way. Used when
creating graphs of elements.
"""
def LoadBalancerFactory (saddr, servers):
    """
    Factory for load balancer. Load balancers are special in the sense that
    they require initialization after the entire graph is set up.
    """
    def InitLoadBalancer (graph, lb):
        servers = map(lambda s: graph[s], servers)
        lb.AddServers (servers)
    def CreateLoadBalancer (graph, node):
        lb = LoadBalancer(node, saddr, None, graph.Context)
        graph.AddNodeInitializer (InitLoadBalancer, [graph, lb]) 
        return lb
    return CreateLoadBalancer

def EndHostFactory ():
    """
    Factory for endhosts.
    """
    def CreateEndHost (graph, node):
        return EndHost(node, graph.Network, graph.Context) 
    return CreateEndHost

def AclFirewallFactory ():
    """
    Factory for simple ACL based firewalls.
    """
    def CreateAclFirewall (graph, node):
        return AclFirewall(node, graph.Network, graph.Context) 
    return CreateAclFirewall

def LearningFirewallFactory ():
    """
    Factory for Learning Firewalls.
    """
    def CreateLearningFirewall (graph, node):
        return LearningFirewall(node, graph.Network, graph.Context) 
    return CreateLearningFirewall

def WebProxyFactory ():
    """
    Factory for Web Proxies.
    """
    def CreateWebProxy (graph, node):
        return WebProxy(node, graph.Network, graph.Context) 
    return CreateWebProxy

def IPSFactory (ips_policy):
    """
    Factory for IPS boxes
    """
    def CreateIPS (graph, node):
        return IPS(ips_policy, node, graph.Network, graph.Context)
    return CreateIPS

def WANOptFactory (transformation):
    """
    Factory for transformation box
    """
    def CreateWANOpt (graph, node):
        return WANOptTransformer(transformation, node, graph.Network, graph.Context)
    return CreateWANOpt
