import os, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'mcnet'))
from twolearningfw import *
from withProxySat import *
from withoutProxyAclFw import *
from withoutProxyLearning import *
from dpiFw import *
from dpiCompress import *
from dpiCompress2 import *
from trivial import *
from trivial_wan_opt import *
from trivial_wan_opt_internal import *
from trivial_wan_opt_dpi import *
from trivial_proxy import *
from trivial_proxy_erroneous import *
from trivial_proxy_erroneous_multiple import *
