from . import Core
import z3
import pyprimes
class CompressionAlgorithm (Core):
    """A compression algorithm is a set of two function:
       - compress
       - decompress
       Decompress is the inverse of compress."""
    PRIMES = pyprimes.primes()
    def _init (self, algorithm_name):
        """Algorithm name is used to get unique names"""
        self.name = algorithm_name
        self.const = next(CompressionAlgorithm.PRIMES)
        #self.body_sort = z3.BitVecSort(64)
        self.body_sort = z3.IntSort()
        self.constraints = list ()
        self._createCompressionFunction ()

    def _addConstraints (self, solver):
        solver.add(self.constraints)

    def _createCompressionFunction (self):
        """Declare functions add some constraints to this etc"""
        self.compress = z3.Function ('%s_compress'%(self.name), self.body_sort, self.body_sort)
        self.decompress = z3.Function ('%s_decompress'%(self.name), self.body_sort, self.body_sort)
        uncompressed = z3.Const('__compression_%s_uncompressed'%(self.name), self.body_sort)

        # Assume that compression changes data, because well that makes sense
        self.constraints.append(z3.ForAll([uncompressed], self.compress(uncompressed) == uncompressed + self.const))

        self.constraints.append(z3.ForAll([uncompressed], self.decompress(uncompressed) == uncompressed - self.const))

        # Decompression is the inverse of compression
        self.constraints.append(z3.ForAll([uncompressed],\
                                self.decompress(self.compress(uncompressed)) == uncompressed))

    def packetCompressionPredicate (self, context):
        return lambda p: self.compress(context.packet.body(p))

    def packetDecompressionPredicate (self, context):
        return lambda p: self.decompress(context.packet.body(p))
