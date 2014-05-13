from abc import ABCMeta, abstractmethod, abstractproperty
import z3
# Core component for everything that matters
class Core(object):
    __metaclass__ = ABCMeta
    """This is the core object from which all components in the modeling
    framework are derived"""
    def __init__ (self, *args, **kwargs):
        """Constructors are useful"""
        self._init(*args, **kwargs)
    @abstractmethod
    def _init(self, *args, **kwargs):
        """The constructor calls _init. This allows us to set somethings up in
        the Core"""
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
