from abc import ABCMeta, abstractmethod, abstractproperty

class GraphObject (object):
    __metaclass__ = ABCMeta
    @abstractmethod
    def TranslateToGraph (self, graph):
        """Translate from state in class to graph object"""
        pass

class GraphNode (GraphObject):
    """Represent a graph node in the actual model checking graph. This allows
    policies using nodes to be specified"""
    def __init__ (self, node):
        """Node is whatever is added to nx as the graph node"""
        self.node = node

    def TranslateToGraph (self, graph):
        """Translate from node name to node in graph"""
        return graph.NodeRef(self.node)

class GraphAddr (GraphObject):
    """Represent a graph address in the actual model checking graph. This allows
    policies using nodes to be specified"""
    def __init__ (self, addr):
        """Address is whatever is added to nx as an address"""
        self.addr = addr

    def TranslateToGraph (self, graph):
        """Translate from node address to address in graph"""
        return graph.AddrRef(self.addr)

def TranslateIfTranslatable (graph, obj):
    return obj.TranslateToGraph(graph) if isinstance(obj, GraphObject) else obj

class TranslatableTuple (GraphObject):
    """Tuples which need translating"""
    def __init__ (self, tup):
        self.tup = tup
    def TranslateToGraph (self, graph):
        return tuple(map(lambda o: TranslateIfTranslatable(graph, o), self.tup))

class TranslatableList (GraphObject):
    """Tuples which need translating"""
    def __init__ (self, lst):
        self.lst = lst
    def TranslateToGraph (self, graph):
        return map(lambda o: TranslateIfTranslatable(graph, o), self.lst)

def ConstructAclList (acls):
    return TranslatableList(map(lambda p: TranslatableTuple(tuple(map(GraphAddr, p))), acls)) 
