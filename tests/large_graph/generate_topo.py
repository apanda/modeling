import networkx as nx
import itertools
import mcnet.graphtools 
""" Generate a large graph which is fully connected. Assign them to tenants (and hence equivalence class) at random.
This is really just for testing"""
def FirewallEhGenerator (num_nodes, num_tennants):
    """ Generate a large graph where nodes are connected to a firewall and the firewalls are connected to each other.
    The idea here is that the"""
    graph = nx.Graph ()

