from UserList import UserList


class CategoricalCollection(UserList):
    """A categorical collection is something that I find hard to believe that Python does not have. It merely wraps up a
    list so function calls get mapped to everything"""
    def __getattr__ (self, attr):
        # First we make sure that the attribute actually exists for all
        if any(map(lambda o: not hasattr(o, attr), self.data)):
            raise AttributeError
        attributes = map(lambda o: getattr(o, attr), self.data)
        if any(map(lambda a: not callable(a), attributes)):
            return attributes
        else:
            def _wrapFunction (*arguments):
                map(lambda f: f (*arguments), attributes)
            return _wrapFunction
