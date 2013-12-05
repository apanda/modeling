import networkx as nx
import components

class GraphTopo (object):
    def __init__ (self, graph):
        """Construct a network from a NetworkX graph. The network and context are available in the object
           We expect each node in the supplied graph to have a few attributes:
           1. A factory this takes a node and a reference to  and creates an object from mcnet.components. 
           2. An address: can be a string or a list.
        """
        nodes = graph.nodes()
        # We need node names to be strings
        self.nodes = {'n_%s'%str(node): node for node in nodes}
        self.rev_nodes = {self.nodes[node]: node for node in self.nodes.iterkeys()}
        address_map = nx.get_node_attributes(graph, 'address')
        addresses = address_map.values()
        addresses = list(set(addresses))
        self.addresses = {'a_%s'%str(address) : address for address in addresses}
        self.rev_addresses = {self.addresses[address]: address for address in self.addresses.iterkeys()}
        # Create context and network
        self.ctx = components.Context (self.nodes.keys(), self.addresses.keys())
        self.net = components.Network (self.ctx)
        factories = nx.get_node_attributes(graph, 'factory')
        self.addr_refs = {address: getattr(self.ctx, self.rev_addresses[address]) for address in addresses}

        self.node_initializers = []
        self.node_elements = {}

        for k,v in factories.iteritems():
            self.node_elements[k] =  v (self, getattr(self.ctx, self.rev_nodes[k]))
        
        for init in self.node_initializers:
            func, args = init
            func(*args)
        # Take care of individual nodes
        for node in sorted(self.nodes.keys()):
            adjacent_nodes = map(lambda n: self.node_elements[n], nx.all_neighbors(graph, self.nodes[node]))
            node_obj = self.node_elements [self.nodes[node]]
            ad_map = []
            for k, v in address_map.iteritems():
                k = self.node_elements[k]
                if isinstance(v, list):
                    v = map(self.AddrRef, v)
                else:
                    v = self.AddrRef(v)
                ad_map.append((k, v))
            self.net.setAddressMappings(ad_map)
            # Add adjacency element
            self.net.AdjacentNode (node_obj, adjacent_nodes)
            self.net.Attach (node_obj)

    @property
    def Network (self):
        """ Return the Network"""
        return self.net

    @property
    def Context (self):
        """ Return the context for this graph"""
        return self.ctx

    def AddNodeInitializer (self, func, args):
        self.node_initializers.append(func, args)

    def NodeRef (self, node):
        """Return a reference to a named node for use when using Checker"""
        return self.node_elements[node]

    def AddrRef (self, addr):
        """Return a reference to the address when using Checker"""
        return self.addr_refs[addr]

    def __len__ (self):
        """Number of nodes"""
        return len(nodes.keys())

    def __getitem__ (self, node):
        """Get a particular node"""
        return self.NodeRef(node)

    def __call__ (self, address):
        """Get an address"""
        return self.AddrRef(address)

