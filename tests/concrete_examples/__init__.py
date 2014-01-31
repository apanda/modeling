import os, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'mcnet'))
from lsrr_fw_example import *
from lsrr_fw_example_obv_broken import *
from proxy_appfw import *
from proxy_appfw_scale import *
from dpiFw import *
from perf_test import *
from proxy_appfw_policy import *
from proxy_appfw_policy_scale import *
from appfw_proxy_scale import *
from appfw_proxy_policy_scale import *
from dpiFwRonoTest import *
