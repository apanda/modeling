import networkx as nx
import components

def from_graph (graph):
    """Construct a network from a NetworkX graph. Returns the network and context.
       We expect each node in the supplied graph to have a few attributes:
       1. A factory this takes a node network and context and creates an object  from mcnet.components. 
       2. An address: can be a string or a list.
    """
    nodes = graph.nodes()
    # We need node names to be strings
    nodes = {str(node): node for node in nodes}
    rev_nodes = {node: str(node) for node in nodes}
    address_map = nx.get_node_attributes(graph, 'address')
    addresses = address_map.values()
    addresses = list(set(addresses))
    # Create context and network
    ctx = components.Context (nodes.keys(), addresses)
    net = components.Network (ctx)
    factories = nx.get_node_attributes(graph, 'factory')
    node_elements = {k : v (getattr(ctx, k), net, ctx)\
                        for k, v in factories.iteritems()}
    # Take care of individual nodes
    for node in sorted(nodes.keys()):
        adjacent_nodes = map(lambda n: node_elements[n], nx.all_neighbors(graph, nodes[node]))
        node_obj = node_elements [node]
        # Add adjacency element
        net.AdjacentNode (node_obj, adjacent_nodes)
        net.Attach (node_obj)
    return net, ctx
