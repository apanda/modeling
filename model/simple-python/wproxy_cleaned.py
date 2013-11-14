import z3
from network_model import *

def withProxyUnsat():
    print "Proxy UNSAT"
    model = NetworkModel(['a','b','c','d','fw_eh','proxy'],\
                            ['ada', 'adb', 'adc', 'add', 'fwadd', 'padd'])
    model.setAddressMappingsExclusive({'a':'ada', 'b':'adb','c':'adc','d':'add','fw_eh':'fwadd','proxy':'padd'})
    model.EndHostRules(['a','b'],['fw_eh'])
    model.EndHostRules(['c','d'],['proxy'])
    model.FirewallDenyRules('fw_eh', ['a','b','proxy'], [('ada', 'adc'), ('adb', 'add')])
    model.WebProxyRules('proxy', ['fw_eh','c','d'])
    
    model.RoutingTable('fw_eh', {'ada': 'a',\
                                  'adb': 'b',\
                                  'adc': 'proxy',\
                                  'add': 'proxy',\
                                  'padd': 'proxy'})
    model.RoutingTable('proxy', {'ada':'fw_eh',\
                                 'adb': 'fw_eh',\
                                 'adc': 'c',\
                                 'add': 'd',\
                                 'fwadd': 'fw_eh'}) 
    model.RoutingTable('a', {a: 'fw_eh'\
              for a in ['ada', 'adb','adc','add','fwadd','padd']})
    model.RoutingTable('b', {a: 'fw_eh'\
        for a in ['ada', 'adb','adc','add','fwadd','padd']})
    model.RoutingTable('c', {a: 'proxy'\
            for a in ['ada', 'adb','adc','add','fwadd','padd']})
    model.RoutingTable('d', {a: 'proxy'\
            for a in ['ada', 'adb','adc','add','fwadd','padd']})

    model.CheckPacketReachability('a', 'c')
    model.CheckPacketReachability('b', 'd')
    return model

def withProxySat():
    print "Proxy SAT"
    model = NetworkModel(['a','b','c','d','fw_eh','proxy'],\
                            ['ada', 'adb', 'adc', 'add', 'fwadd', 'padd'])
    model.setAddressMappingsExclusive({'a':'ada', 'b':'adb','c':'adc','d':'add','fw_eh':'fwadd','proxy':'padd'})
    model.EndHostRules(['a','b'],['proxy'])
    model.EndHostRules(['c','d'],['fw_eh'])
    model.FirewallDenyRules('fw_eh', ['c','d','proxy'], [('ada', 'adc'), ('adb', 'add')])
    model.WebProxyRules('proxy', ['fw_eh','a','b'])

    model.RoutingTable('proxy', {'ada': 'a',\
                                 'adb': 'b',\
                                 'adc': 'fw_eh',\
                                 'add': 'fw_eh',\
                                 'fwadd': 'fw_eh'})
    
    model.RoutingTable('fw_eh', {'ada': 'proxy',\
                                 'adb': 'proxy',\
                                 'adc': 'c',\
                                 'add': 'd',\
                                 'padd': 'proxy'})
    model.RoutingTable('a', {a: 'proxy'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd', 'padd']})
    model.RoutingTable('b', {a: 'proxy'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd', 'padd']})
    model.RoutingTable('c', {a: 'fw_eh'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd', 'padd']})
    model.RoutingTable('d', {a: 'fw_eh'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd', 'padd']})

    model.CheckPacketReachability('a', 'd')
    model.CheckPacketReachability('b', 'c')
    return model

def withoutProxy():
    print "No PROXY SAT"
    model = NetworkModel(['a','b','c','d','fw_eh'],\
                            ['ada', 'adb', 'adc', 'add', 'fwadd'])
    model.setAddressMappingsExclusive({'a':'ada', 'b':'adb','c':'adc','d':'add','fw_eh':'fwadd'})
    model.EndHostRules(['a','b','c','d'],['fw_eh'])
    model.FirewallDenyRules('fw_eh', ['a','b','c','d'], [('ada', 'adc'), ('adb', 'add')])
    model.RoutingTable('fw_eh', {'ada': 'a',\
                                 'adb': 'b',\
                                 'adc': 'c',\
                                 'add': 'd'})
    model.RoutingTable('a', {a: 'fw_eh'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd']})
    model.RoutingTable('b', {a: 'fw_eh'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd']})
    model.RoutingTable('c', {a: 'fw_eh'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd']})
    model.RoutingTable('d', {a: 'fw_eh'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd']})
    model.RoutingTable('a', {a: 'fw_eh'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd']})
    model.CheckPacketReachability('a', 'b')
    return model

def withoutProxyLearning():
    print "No PROXY, Learning Firewall, SHOULD BE UNSAT"
    model = NetworkModel(['a','b','c','d','fw_eh'],\
                            ['ada', 'adb', 'adc', 'add', 'fwadd'])
    model.setAddressMappingsExclusive({'a':'ada', 'b':'adb','c':'adc','d':'add','fw_eh':'fwadd'})
    model.EndHostRules(['a','b','c','d'],['fw_eh'])
    model.LearningFirewallRules('fw_eh', ['a','b','c','d'], [('ada', 'adc'), ('adc', 'ada'), ('adb', 'add')])
    model.RoutingTable('fw_eh', {'ada': 'a',\
                                 'adb': 'b',\
                                 'adc': 'c',\
                                 'add': 'd'})
    model.RoutingTable('a', {a: 'fw_eh'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd']})
    model.RoutingTable('b', {a: 'fw_eh'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd']})
    model.RoutingTable('c', {a: 'fw_eh'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd']})
    model.RoutingTable('d', {a: 'fw_eh'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd']})
    model.RoutingTable('a', {a: 'fw_eh'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd']})
    model.CheckPacketReachability('a', 'c')
    model.CheckPacketReachability('b', 'd')
    return model

def withProxyLearningCorrect():
    print "Proxy, Learning Firwall (correct) SAT"
    model = NetworkModel(['a','b','c','d','fw_eh','proxy'],\
                            ['ada', 'adb', 'adc', 'add', 'fwadd', 'padd'])
    model.setAddressMappingsExclusive({'a':'ada', 'b':'adb','c':'adc','d':'add','fw_eh':'fwadd','proxy':'padd'})
    model.EndHostRules(['a','b'],['proxy'])
    model.EndHostRules(['c','d'],['fw_eh'])
    model.LearningFirewallRules('fw_eh', ['c','d','proxy'], [('ada', 'adc'), ('adb', 'add'), ('add', 'adb'), ('adc', 'ada')])
    model.WebProxyRules('proxy', ['fw_eh','a','b'])
    model.RoutingTable('proxy', {'ada': 'a',\
                                 'adb': 'b',\
                                 'adc': 'fw_eh',\
                                 'add': 'fw_eh',\
                                 'fwadd': 'fw_eh'})
    
    model.RoutingTable('fw_eh', {'ada': 'proxy',\
                                 'adb': 'proxy',\
                                 'adc': 'c',\
                                 'add': 'd',\
                                 'padd': 'proxy'})
    model.RoutingTable('a', {a: 'proxy'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd', 'padd']})
    model.RoutingTable('b', {a: 'proxy'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd', 'padd']})
    model.RoutingTable('c', {a: 'fw_eh'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd', 'padd']})
    model.RoutingTable('d', {a: 'fw_eh'\
                    for a in ['ada', 'adb', 'adc', 'add', 'fwadd', 'padd']})
    model.CheckPacketReachability('a', 'd')
    model.CheckPacketReachability('b', 'c')
    return model

def withProxyLearningCorrectUnsat():
    print "Proxy, Learning Firwall (correct) UNSAT"
    model = NetworkModel(['a','b','c','d','fw_eh','proxy'],\
                            ['ada', 'adb', 'adc', 'add', 'fwadd', 'padd'])
    model.setAddressMappingsExclusive({'a':'ada', 'b':'adb','c':'adc','d':'add','fw_eh':'fwadd','proxy':'padd'})
    model.EndHostRules(['a','b'],['fw_eh'])
    model.EndHostRules(['c','d'],['proxy'])
    model.LearningFirewallRules('fw_eh', ['a','b','proxy'], [('ada', 'adc'), ('adb', 'add'), ('add', 'adb'), ('adc', 'ada')])
    model.WebProxyRules('proxy', ['fw_eh','c','d'])

    model.RoutingTable('fw_eh', {'ada': 'a',\
                                  'adb': 'b',\
                                  'adc': 'proxy',\
                                  'add': 'proxy',\
                                  'padd': 'proxy'})
    model.RoutingTable('proxy', {'ada':'fw_eh',\
                                 'adb': 'fw_eh',\
                                 'adc': 'c',\
                                 'add': 'd',\
                                 'fwadd': 'fw_eh'}) 
    model.RoutingTable('a', {a: 'fw_eh'\
              for a in ['ada', 'adb','adc','add','fwadd','padd']})
    model.RoutingTable('b', {a: 'fw_eh'\
        for a in ['ada', 'adb','adc','add','fwadd','padd']})
    model.RoutingTable('c', {a: 'proxy'\
            for a in ['ada', 'adb','adc','add','fwadd','padd']})
    model.RoutingTable('d', {a: 'proxy'\
            for a in ['ada', 'adb','adc','add','fwadd','padd']})

    model.CheckPacketReachability('a', 'c')
    model.CheckPacketReachability('b', 'd')
    return model

def withProxyLearningIncorrectSat():
    print "Proxy, Learning Firwall (incorrect) SAT"
    model = NetworkModel(['a','b','c','d','fw_eh','proxy'],\
                            ['ada', 'adb', 'adc', 'add', 'fwadd', 'padd'])
    model.setAddressMappingsExclusive({'a':'ada', 'b':'adb','c':'adc','d':'add','fw_eh':'fwadd','proxy':'padd'})
    model.EndHostRules(['a','b'],['fw_eh'])
    model.EndHostRules(['c','d'],['proxy'])
    model.LearningFirewallRules('fw_eh', ['a','b','proxy'], [('ada', 'adc'), ('adb', 'add')])
    model.WebProxyRules('proxy', ['fw_eh','c','d'])

    model.RoutingTable('fw_eh', {'ada': 'a',\
                                  'adb': 'b',\
                                  'adc': 'proxy',\
                                  'add': 'proxy',\
                                  'padd': 'proxy'})
    model.RoutingTable('proxy', {'ada':'fw_eh',\
                                 'adb': 'fw_eh',\
                                 'adc': 'c',\
                                 'add': 'd',\
                                 'fwadd': 'fw_eh'}) 
    model.RoutingTable('a', {a: 'fw_eh'\
              for a in ['ada', 'adb','adc','add','fwadd','padd']})
    model.RoutingTable('b', {a: 'fw_eh'\
        for a in ['ada', 'adb','adc','add','fwadd','padd']})
    model.RoutingTable('c', {a: 'proxy'\
            for a in ['ada', 'adb','adc','add','fwadd','padd']})
    model.RoutingTable('d', {a: 'proxy'\
            for a in ['ada', 'adb','adc','add','fwadd','padd']})

    model.CheckPacketReachability('a', 'd')
    model.CheckPacketReachability('b', 'c')
    return model

if __name__ == "__main__":
    funcs = [withProxySat,\
            withoutProxy,\
            withoutProxyLearning,\
            withProxyUnsat,\
            withProxyLearningCorrect,\
            withProxyLearningIncorrectSat,\
            withProxyLearningCorrectUnsat]
    #funcs = [withProxyLearningCorrect]
    for func in funcs:
        model = func()
        result =  model.solver.check ()
        print result
        if result == z3.sat:
            solution =  model.solver.model ()
            print solution
