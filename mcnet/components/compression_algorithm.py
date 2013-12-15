from . import Core
import z3
class CompressionAlgorithm (Core):
    """A compression algorithm is a set of two function:
       - compress
       - decompress
       Decompress is the inverse of compress."""

    def _init (self, algorithm_name):
        """Algorithm name is used to get unique names"""
        self.name = algorithm_name
        self.constraints = list ()
        self._createCompressionFunction ()

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def _createCompressionFunction (self):
        """Declare functions add some constraints to this etc"""
        self.compress = z3.Function (z3.IntSort(), z3.IntSort())
        self.decompress = z3.Function (z3.IntSort(), z3.IntSort())
        uncompressed = z3.Int('__compression_%s_uncompressed'%(self.name))
        compressed = z3.Int('__compression_%s_compressed'%(self.name))

        # Assume that compression changes data, because well that makes sense
        self.constraints.append(self.compress(uncompressed) != uncompressed) 
        
        # Decompression is the inverse of compression
        self.constraints.append(z3.Implies(compressed == self.compress(uncompressed), \
                                           uncompressed == self.decompress(compressed)))
