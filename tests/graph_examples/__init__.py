import os, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'mcnet'))
from eh_acl_fw import GraphAclFwNoProxy 
from eh_learn_fw import GraphLearnFwNoProxy
from eh_learn_proxy_learn_eh import GraphLearn2FwProxy
from eh_learn_proxy_eh import GraphLearnFwProxy
