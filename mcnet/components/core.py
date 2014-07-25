from abc import ABCMeta, abstractmethod, abstractproperty
import z3
# Core component for everything that matters
class Core(object):
    __metaclass__ = ABCMeta
    MAX_PORT = 512
    """Base class for all objects in the modeling framework"""
    def __init__ (self, *args, **kwargs):
        self._init(*args, **kwargs)
    @abstractmethod
    def _init(self, *args, **kwargs):
        """Override _init for any constructor initialization. Avoids
        having to explicitly call super.__init__ every time."""
        pass
    @abstractmethod
    def _addConstraints (self, solver):
        """Add constraints to solver"""
        pass

class NetworkObject(Core):
    __metaclass__ = ABCMeta
    @abstractproperty
    def z3Node (self):
        """Get a reference to the z3 node this class wraps around"""
        pass
    def __str__ (self):
        return str(self.z3Node)
    def __hash__ (self):
        return self.z3Node.__hash__()
    @property
    def isEndHost (self):
        """A simple way to determine the set of endhosts"""
        return False
    def SetPolicy (self, policy):
        """Wrap methods to set policy"""
        raise NotImplementedError
