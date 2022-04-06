import pyAgrum as gum
from pylab import *
import matplotlib.pyplot as plt
import os

# import pyAgrum.lib.notebook as gnb

# bn = gum.BayesNet('RiskAssessment')
# print(bn)
#
# # Create Nodes
#
# te1 = bn.add(gum.LabelizedVariable('te1', 'Threat Exposure 1', 2))
# re1 = bn.add(gum.LabelizedVariable('re1', 'Response 1', 2))
# mat1 = bn.add(gum.LabelizedVariable('mat1', 'Materialisation 1', 2))
# mat2 = bn.add(gum.LabelizedVariable('mat2', 'Materialisation 2', 2))
# mat3 = bn.add(gum.LabelizedVariable('mat3', 'Materialisation 3', 2))
# mat4 = bn.add(gum.LabelizedVariable('mat4', 'Materialisation 4', 2))
# mat5 = bn.add(gum.LabelizedVariable('mat5', 'Materialisation 5', 2))
# con1 = bn.add(gum.LabelizedVariable('con1', 'Consequence 1', 2))
# con2 = bn.add(gum.LabelizedVariable('con2', 'Consequence 2', 2))
# con3 = bn.add(gum.LabelizedVariable('con3', 'Consequence 3', 2))
# con4 = bn.add(gum.LabelizedVariable('con4', 'Consequence 4', 2))
# con5 = bn.add(gum.LabelizedVariable('con5', 'Consequence 5', 2))
# ass1 = bn.add(gum.LabelizedVariable('ass1', 'Asset 1', 2))
# imp1 = bn.add(gum.LabelizedVariable('imp1', 'Impact 1', 4))
# imp2 = bn.add(gum.LabelizedVariable('imp2', 'Impact 2', 4))
# imp3 = bn.add(gum.LabelizedVariable('imp3', 'Impact 3', 4))
# imp4 = bn.add(gum.LabelizedVariable('imp4', 'Impact 4', 4))
# imp5 = bn.add(gum.LabelizedVariable('imp5', 'Impact 5', 4))
# obj1 = bn.add(gum.LabelizedVariable('obj1', 'Objective 1', 5))
# obj2 = bn.add(gum.LabelizedVariable('obj2', 'Objective 1', 5))
# obj3 = bn.add(gum.LabelizedVariable('obj3', 'Objective 1', 5))
# obj4 = bn.add(gum.LabelizedVariable('obj4', 'Objective 1', 5))
# obj5 = bn.add(gum.LabelizedVariable('obj5', 'Objective 1', 5))
#
# # Connect Tables
# bn.addArc(te1, mat1)
# bn.addArc(te1, mat2)
# bn.addArc(te1, mat3)
# bn.addArc(te1, mat4)
# bn.addArc(te1, mat5)
#
# bn.addArc(re1, mat1)
# bn.addArc(re1, mat2)
# bn.addArc(re1, mat3)
# bn.addArc(re1, mat4)
# bn.addArc(re1, mat5)
#
# bn.addArc(mat1, con1)
# bn.addArc(mat2, con2)
# bn.addArc(mat3, con3)
# bn.addArc(mat4, con4)
# bn.addArc(mat5, con5)
#
# bn.addArc(ass1, imp1)
# bn.addArc(ass1, imp2)
# bn.addArc(ass1, imp3)
# bn.addArc(ass1, imp4)
# bn.addArc(ass1, imp5)
#
# bn.addArc(con1, imp1)
# bn.addArc(con1, imp2)
#
# bn.addArc(con2, imp1)
# bn.addArc(con2, imp3)
#
# bn.addArc(con3, imp1)
# bn.addArc(con3, imp4)
#
# bn.addArc(con4, imp2)
# bn.addArc(con4, imp3)
#
# bn.addArc(con5, imp5)
#
# bn.addArc(imp1, obj1)
# bn.addArc(imp1, obj2)
# bn.addArc(imp1, obj3)
# bn.addArc(imp1, obj4)
#
# bn.addArc(imp2, obj1)
# bn.addArc(imp2, obj2)
# bn.addArc(imp2, obj3)
# bn.addArc(imp2, obj4)
#
# bn.addArc(imp3, obj1)
# bn.addArc(imp3, obj2)
# bn.addArc(imp3, obj3)
# bn.addArc(imp3, obj4)
#
# bn.addArc(imp4, obj2)
# bn.addArc(imp4, obj5)
#
# # Fill tables
# bn.cpt(te1).fillWith([0.7, 0.5])
# bn.cpt(re1).fillWith([0.5, 0.5])
# bn.cpt(mat1)[{'te1': 0, 're1': 0}] = [0.3, 0.7]
# bn.cpt(mat1)[{'te1': 0, 're1': 1}] = [0.3, 0.7]
# bn.cpt(mat1)[{'te1': 1, 're1': 0}] = [0.3, 0.7]
# bn.cpt(mat1)[{'te1': 1, 're1': 1}] = [0.3, 0.7]
#
# bn.cpt(mat2)[{'te1': 0, 're1': 0}] = [0.3, 0.7]
# bn.cpt(mat2)[{'te1': 0, 're1': 1}] = [0.3, 0.7]
# bn.cpt(mat2)[{'te1': 1, 're1': 0}] = [0.3, 0.7]
# bn.cpt(mat2)[{'te1': 1, 're1': 1}] = [0.3, 0.7]
#
# bn.cpt(mat3)[{'te1': 0, 're1': 0}] = [0.3, 0.7]
# bn.cpt(mat3)[{'te1': 0, 're1': 1}] = [0.3, 0.7]
# bn.cpt(mat3)[{'te1': 1, 're1': 0}] = [0.3, 0.7]
# bn.cpt(mat3)[{'te1': 1, 're1': 1}] = [0.3, 0.7]
#
# bn.cpt(mat4)[{'te1': 0, 're1': 0}] = [0.3, 0.7]
# bn.cpt(mat4)[{'te1': 0, 're1': 1}] = [0.3, 0.7]
# bn.cpt(mat4)[{'te1': 1, 're1': 0}] = [0.3, 0.7]
# bn.cpt(mat4)[{'te1': 1, 're1': 1}] = [0.3, 0.7]
#
# bn.cpt(mat5)[{'te1': 0, 're1': 0}] = [0.3, 0.7]
# bn.cpt(mat5)[{'te1': 0, 're1': 1}] = [0.3, 0.7]
# bn.cpt(mat5)[{'te1': 1, 're1': 0}] = [0.3, 0.7]
# bn.cpt(mat5)[{'te1': 1, 're1': 1}] = [0.3, 0.7]
#
# bn.cpt(con1)[{'mat1': 0}] = [0.3, 0.7]
# bn.cpt(con1)[{'mat1': 1}] = [0.7, 0.3]
#
# bn.cpt(con2)[{'mat2': 0}] = [0.3, 0.7]
# bn.cpt(con2)[{'mat2': 1}] = [0.7, 0.3]
#
# bn.cpt(con3)[{'mat3': 0}] = [0.3, 0.7]
# bn.cpt(con3)[{'mat3': 1}] = [0.7, 0.3]
#
# bn.cpt(con4)[{'mat4': 0}] = [0.3, 0.7]
# bn.cpt(con4)[{'mat4': 1}] = [0.7, 0.3]
#
# bn.cpt(con5)[{'mat5': 0}] = [0.3, 0.7]
# bn.cpt(con5)[{'mat5': 1}] = [0.7, 0.3]
#
# bn.cpt(ass1).fillWith([0.5, 0.5])
#
# bn.cpt(imp1)[{'ass1': 0, 'con1': 0, 'con2': 0, 'con3': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 1, 'con1': 0, 'con2': 0, 'con3': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 0, 'con1': 1, 'con2': 0, 'con3': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 1, 'con1': 1, 'con2': 0, 'con3': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 0, 'con1': 0, 'con2': 1, 'con3': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 1, 'con1': 0, 'con2': 1, 'con3': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 0, 'con1': 1, 'con2': 1, 'con3': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 1, 'con1': 1, 'con2': 1, 'con3': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 0, 'con1': 0, 'con2': 0, 'con3': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 1, 'con1': 0, 'con2': 0, 'con3': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 0, 'con1': 1, 'con2': 0, 'con3': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 1, 'con1': 1, 'con2': 0, 'con3': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 0, 'con1': 0, 'con2': 1, 'con3': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 1, 'con1': 0, 'con2': 1, 'con3': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 0, 'con1': 1, 'con2': 1, 'con3': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp1)[{'ass1': 1, 'con1': 1, 'con2': 1, 'con3': 1}] = [0.3, 0.3, 0.2, 0.2]
#
# bn.cpt(imp2)[{'ass1': 0, 'con1': 0, 'con4': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp2)[{'ass1': 1, 'con1': 0, 'con4': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp2)[{'ass1': 0, 'con1': 1, 'con4': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp2)[{'ass1': 1, 'con1': 1, 'con4': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp2)[{'ass1': 0, 'con1': 0, 'con4': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp2)[{'ass1': 1, 'con1': 0, 'con4': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp2)[{'ass1': 0, 'con1': 1, 'con4': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp2)[{'ass1': 1, 'con1': 1, 'con4': 1}] = [0.3, 0.3, 0.2, 0.2]
#
# bn.cpt(imp3)[{'ass1': 0, 'con2': 0, 'con4': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp3)[{'ass1': 1, 'con2': 0, 'con4': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp3)[{'ass1': 0, 'con2': 1, 'con4': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp3)[{'ass1': 1, 'con2': 1, 'con4': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp3)[{'ass1': 0, 'con2': 0, 'con4': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp3)[{'ass1': 1, 'con2': 0, 'con4': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp3)[{'ass1': 0, 'con2': 1, 'con4': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp3)[{'ass1': 1, 'con2': 1, 'con4': 1}] = [0.3, 0.3, 0.2, 0.2]
#
# bn.cpt(imp4)[{'ass1': 0, 'con3': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp4)[{'ass1': 1, 'con3': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp4)[{'ass1': 0, 'con3': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp4)[{'ass1': 1, 'con3': 1}] = [0.3, 0.3, 0.2, 0.2]
#
# bn.cpt(imp5)[{'ass1': 0, 'con5': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp5)[{'ass1': 1, 'con5': 0}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp5)[{'ass1': 0, 'con5': 1}] = [0.3, 0.3, 0.2, 0.2]
# bn.cpt(imp5)[{'ass1': 1, 'con5': 1}] = [0.3, 0.3, 0.2, 0.2]
#
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 0, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 0, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 0, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 0, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 1, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 1, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 1, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 1, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 2, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 2, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 2, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 2, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 3, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 3, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 3, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 3, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 0, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 0, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 0, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 0, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 1, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 1, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 1, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 1, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 2, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 2, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 2, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 2, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 3, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 3, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 3, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 3, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 0, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 0, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 0, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 0, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 1, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 1, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 1, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 1, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 2, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 2, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 2, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 2, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 3, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 3, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 3, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 3, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 0, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 0, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 0, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 0, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 1, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 1, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 1, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 1, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 2, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 2, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 2, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 2, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 0, 'imp2': 3, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 1, 'imp2': 3, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 2, 'imp2': 3, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj1)[{'imp1': 3, 'imp2': 3, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
#
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 0, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 1, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 2, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 3, 'imp4': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
#
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 0, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 1, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 2, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 3, 'imp4': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
#
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 0, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 1, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 2, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 3, 'imp4': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
#
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 0, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 1, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 2, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 0, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 1, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 2, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 0, 'imp2': 3, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 1, 'imp2': 3, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 2, 'imp2': 3, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj2)[{'imp1': 3, 'imp2': 3, 'imp3': 3, 'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
#
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 0, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 0, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 0, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 0, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 1, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 1, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 1, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 1, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 2, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 2, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 2, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 2, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 3, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 3, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 3, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 3, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 0, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 0, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 0, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 0, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 1, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 1, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 1, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 1, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 2, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 2, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 2, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 2, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 3, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 3, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 3, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 3, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 0, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 0, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 0, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 0, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 1, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 1, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 1, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 1, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 2, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 2, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 2, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 2, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 3, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 3, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 3, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 3, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 0, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 0, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 0, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 0, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 1, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 1, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 1, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 1, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 2, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 2, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 2, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 2, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 0, 'imp2': 3, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 1, 'imp2': 3, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 2, 'imp2': 3, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj3)[{'imp1': 3, 'imp2': 3, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
#
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 0, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 0, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 0, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 0, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 1, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 1, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 1, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 1, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 2, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 2, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 2, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 2, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 3, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 3, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 3, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 3, 'imp3': 0}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 0, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 0, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 0, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 0, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 1, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 1, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 1, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 1, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 2, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 2, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 2, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 2, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 3, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 3, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 3, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 3, 'imp3': 1}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 0, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 0, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 0, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 0, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 1, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 1, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 1, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 1, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 2, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 2, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 2, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 2, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 3, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 3, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 3, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 3, 'imp3': 2}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 0, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 0, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 0, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 0, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 1, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 1, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 1, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 1, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 2, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 2, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 2, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 2, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 0, 'imp2': 3, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 1, 'imp2': 3, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 2, 'imp2': 3, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
# bn.cpt(obj4)[{'imp1': 3, 'imp2': 3, 'imp3': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
#
# bn.cpt(obj5)[{'imp4': 0}] = [0.2, 0.1, 0.3, 0.1, 0.1]
# bn.cpt(obj5)[{'imp4': 1}] = [0.1, 0.1, 0.1, 0.1, 0.5]
# bn.cpt(obj5)[{'imp4': 2}] = [0.5, 0.2, 0.05, 0.2, 0.05]
# bn.cpt(obj5)[{'imp4': 3}] = [0.3, 0.2, 0.2, 0.2, 0.1]
#
#
# # Save Graph
# print(os.path.join("out", "WaterSprinkler.bif"))
# gum.saveBN(bn, os.path.join("out", "WaterSprinkler.bif"))
#
# gum.saveBN(bn, os.path.join("out", "WaterSprinkler.net"))
#
# # Print Graph
# with open(os.path.join("out", "WaterSprinkler.bif"), "r") as out:
#     print(out.read())
#
# with open(os.path.join("out", "WaterSprinkler.net"), "r") as out:
#     print(out.read())
#
# ie = gum.LazyPropagation(bn)
# ie.setEvidence({'te1': '1', 're1': '1', 'ass1': '0'})
# ie.makeInference()
# print(f"In our BN, $P(obj1)=${ie.posterior(obj5)[:]}")
#
# gibbs = gum.GibbsSampling(bn)  #
# gibbs.makeInference()
# print(f"In our BN, $P(obj1)=${gibbs.posterior(obj5)[:]}")

# for link in [(c, r), (s, w), (r, w)]:
#     bn.addArc(*link)
#
# print(bn)
#
# bn.cpt(c).fillWith([0.5, 0.5])
# bn.cpt(s)[:] = [[0.5, 0.5], [0.9, 0.1]]
# print(bn.cpt(s)[1])
#
# bn.cpt(w)[0, 0, :] = [1, 0]  # r=0,s=0
# bn.cpt(w)[0, 1, :] = [0.1, 0.9]  # r=0,s=1
# bn.cpt(w)[1, 0, :] = [0.1, 0.9]  # r=1,s=0
# bn.cpt(w)[1, 1, :] = [0.01, 0.99]  # r=1,s=1
#
# bn.cpt(r)[{'c': 0}] = [0.8, 0.2]
# bn.cpt(r)[{'c': 1}] = [0.2, 0.8]
#
# bn.cpt(w)[{'r': 0, 's': 0}] = [1, 0]
# bn.cpt(w)[{'r': 0, 's': 1}] = [0.1, 0.9]
# bn.cpt(w)[{'r': 1, 's': 0}] = [0.1, 0.9]
# bn.cpt(w)[{'r': 1, 's': 1}] = [0.01, 0.99]
# bn.cpt(w)
#
# print(gum.availableBNExts())
# print(os.path.join("out", "WaterSprinkler.bif"))
# gum.saveBN(bn, os.path.join("out", "WaterSprinkler.bif"))
#
# with open(os.path.join("out", "WaterSprinkler.bif"), "r") as out:
#     print(out.read())
#
# ie = gum.LazyPropagation(bn)
# ie.makeInference()
# print(ie.posterior(w))
#
# ie.setEvidence({'s':0, 'c': 0})
# ie.makeInference()
# print(ie.posterior(w))


diag = gum.InfluenceDiagram()

te1 = diag.add(gum.LabelizedVariable('te1', 'Threat Exposure 1', 2))
re1 = diag.addDecisionNode(gum.LabelizedVariable('re1', "Response 1", 2))
# re1 = diag.add(gum.LabelizedVariable('re1', 'Response 1', 2))
mat1 = diag.add(gum.LabelizedVariable('mat1', 'Materialisation 1', 2))
mat2 = diag.add(gum.LabelizedVariable('mat2', 'Materialisation 2', 2))
mat3 = diag.add(gum.LabelizedVariable('mat3', 'Materialisation 3', 2))
mat4 = diag.add(gum.LabelizedVariable('mat4', 'Materialisation 4', 2))
mat5 = diag.add(gum.LabelizedVariable('mat5', 'Materialisation 5', 2))
con1 = diag.add(gum.LabelizedVariable('con1', 'Consequence 1', 2))
con2 = diag.add(gum.LabelizedVariable('con2', 'Consequence 2', 2))
con3 = diag.add(gum.LabelizedVariable('con3', 'Consequence 3', 2))
con4 = diag.add(gum.LabelizedVariable('con4', 'Consequence 4', 2))
con5 = diag.add(gum.LabelizedVariable('con5', 'Consequence 5', 2))
con6 = diag.add(gum.LabelizedVariable('con6', 'Consequence 6', 2))

ass1 = diag.addDecisionNode(gum.LabelizedVariable('ass1', "Asset 1 Node", 2))
ass2 = diag.addDecisionNode(gum.LabelizedVariable('ass2', "Asset 1 Node", 2))
# ass1 = diag.add(gum.LabelizedVariable('ass1', 'Asset 1', 2))
imp1 = diag.add(gum.LabelizedVariable('imp1', 'Business Continuity', 3))
imp2 = diag.add(gum.LabelizedVariable('imp2', 'Reputation', 3))
imp3 = diag.add(gum.LabelizedVariable('imp3', 'Compliance', 3))
imp5 = diag.add(gum.LabelizedVariable('imp5', 'Data Integrity', 3))
imp6 = diag.add(gum.LabelizedVariable('imp6', 'Infrastructure', 3))
imp7 = diag.add(gum.LabelizedVariable('imp7', 'Individual Safety', 3))

obj1 = diag.add(gum.LabelizedVariable('obj1', 'Confidentiality', 3))
obj2 = diag.add(gum.LabelizedVariable('obj2', 'Integrity', 3))
obj3 = diag.add(gum.LabelizedVariable('obj3', 'Availability', 3))
obj4 = diag.add(gum.LabelizedVariable('obj4', 'Monetary', 3))
obj5 = diag.add(gum.LabelizedVariable('obj5', 'Safety', 3))

util1 = diag.addUtilityNode(gum.LabelizedVariable('util1', 'util1', 1))
util2 = diag.addUtilityNode(gum.LabelizedVariable('util2', 'util2', 1))

# Connect Tables
diag.addArc(te1, mat1)
diag.addArc(te1, mat2)
diag.addArc(te1, mat3)
diag.addArc(te1, mat4)
diag.addArc(te1, mat5)

diag.addArc(re1, mat1)
diag.addArc(re1, mat2)
diag.addArc(re1, mat3)
diag.addArc(re1, mat4)
diag.addArc(re1, mat5)
diag.addArc(re1, con6)

diag.addArc(mat1, con1)
diag.addArc(mat2, con2)
diag.addArc(mat3, con3)
diag.addArc(mat4, con4)
diag.addArc(mat5, con5)

diag.addArc(ass1, imp1)
diag.addArc(ass1, imp2)
diag.addArc(ass1, imp7)

diag.addArc(ass2, imp2)
diag.addArc(ass2, imp3)
diag.addArc(ass2, imp7)

diag.addArc(con1, imp1)
diag.addArc(con1, imp2)
diag.addArc(con1, imp7)

diag.addArc(con2, imp1)
diag.addArc(con2, imp3)
diag.addArc(con2, imp6)

diag.addArc(con3, imp1)
diag.addArc(con3, imp5)
diag.addArc(con3, imp6)

diag.addArc(con4, imp2)
diag.addArc(con4, imp3)
diag.addArc(con4, imp6)
diag.addArc(con4, imp7)

diag.addArc(con5, imp6)

diag.addArc(con6, imp1)

diag.addArc(imp1, obj1)
diag.addArc(imp1, obj2)
diag.addArc(imp1, obj3)
diag.addArc(imp1, obj4)

diag.addArc(imp2, obj1)
diag.addArc(imp2, obj2)
diag.addArc(imp2, obj3)
diag.addArc(imp2, obj4)

diag.addArc(imp3, obj1)
diag.addArc(imp3, obj2)
diag.addArc(imp3, obj3)
diag.addArc(imp3, obj4)

diag.addArc(imp5, obj2)
diag.addArc(imp5, obj5)

diag.addArc(imp6, obj3)
diag.addArc(imp6, obj4)
diag.addArc(imp6, obj5)

diag.addArc(imp7, obj5)

diag.addArc(obj1, util1)
diag.addArc(obj2, util1)
diag.addArc(obj3, util1)

diag.addArc(obj4, util2)
diag.addArc(obj5, util2)

# Fill tables
diag.cpt(te1).fillWith([0.7, 0.5])

diag.cpt(mat1)[{'te1': 0, 're1': 0}] = [0.3, 0.7]
diag.cpt(mat1)[{'te1': 0, 're1': 1}] = [0.2, 0.6]
diag.cpt(mat1)[{'te1': 1, 're1': 0}] = [0.5, 0.5]
diag.cpt(mat1)[{'te1': 1, 're1': 1}] = [0.6, 0.4]

diag.cpt(mat2)[{'te1': 0, 're1': 0}] = [0.2, 0.8]
diag.cpt(mat2)[{'te1': 0, 're1': 1}] = [0.3, 0.7]
diag.cpt(mat2)[{'te1': 1, 're1': 0}] = [0.6, 0.4]
diag.cpt(mat2)[{'te1': 1, 're1': 1}] = [0.4, 0.6]

diag.cpt(mat3)[{'te1': 0, 're1': 0}] = [0.1, 0.9]
diag.cpt(mat3)[{'te1': 0, 're1': 1}] = [0.1, 0.9]
diag.cpt(mat3)[{'te1': 1, 're1': 0}] = [0.9, 0.1]
diag.cpt(mat3)[{'te1': 1, 're1': 1}] = [0.9, 0.1]

diag.cpt(mat4)[{'te1': 0, 're1': 0}] = [0.2, 0.8]
diag.cpt(mat4)[{'te1': 0, 're1': 1}] = [0.3, 0.7]
diag.cpt(mat4)[{'te1': 1, 're1': 0}] = [0.1, 0.9]
diag.cpt(mat4)[{'te1': 1, 're1': 1}] = [0.4, 0.6]

diag.cpt(mat5)[{'te1': 0, 're1': 0}] = [0.3, 0.7]
diag.cpt(mat5)[{'te1': 0, 're1': 1}] = [0.3, 0.7]
diag.cpt(mat5)[{'te1': 1, 're1': 0}] = [0.7, 0.3]
diag.cpt(mat5)[{'te1': 1, 're1': 1}] = [0.7, 0.3]

diag.cpt(con1)[{'mat1': 0}] = [0.3, 0.7]
diag.cpt(con1)[{'mat1': 1}] = [0.7, 0.3]

diag.cpt(con2)[{'mat2': 0}] = [0.4, 0.6]
diag.cpt(con2)[{'mat2': 1}] = [0.6, 0.4]

diag.cpt(con3)[{'mat3': 0}] = [0.5, 0.5]
diag.cpt(con3)[{'mat3': 1}] = [0.5, 0.5]

diag.cpt(con4)[{'mat4': 0}] = [0.3, 0.7]
diag.cpt(con4)[{'mat4': 1}] = [0.7, 0.3]

diag.cpt(con5)[{'mat5': 0}] = [0.2, 0.8]
diag.cpt(con5)[{'mat5': 1}] = [0.8, 0.2]

diag.cpt(con6)[{'re1': 0}] = [1, 0]
diag.cpt(con6)[{'re1': 1}] = [0, 1]
#
# diag.cpt(ass1).fillWith([0.5, 0.5])
#
diag.cpt(imp1)[{'ass1': 0, 'con1': 0, 'con2': 0, 'con3': 0, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 0, 'con2': 0, 'con3': 0, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 0, 'con1': 1, 'con2': 0, 'con3': 0, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 1, 'con2': 0, 'con3': 0, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 0, 'con1': 0, 'con2': 1, 'con3': 0, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 0, 'con2': 1, 'con3': 0, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 0, 'con1': 1, 'con2': 1, 'con3': 0, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 1, 'con2': 1, 'con3': 0, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 0, 'con1': 0, 'con2': 0, 'con3': 1, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 0, 'con2': 0, 'con3': 1, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 0, 'con1': 1, 'con2': 0, 'con3': 1, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 1, 'con2': 0, 'con3': 1, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 0, 'con1': 0, 'con2': 1, 'con3': 1, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 0, 'con2': 1, 'con3': 1, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 0, 'con1': 1, 'con2': 1, 'con3': 1, 'con6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 1, 'con2': 1, 'con3': 1, 'con6': 0}] = [0.3, 0.3, 0.4]

diag.cpt(imp1)[{'ass1': 0, 'con1': 0, 'con2': 0, 'con3': 0, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 0, 'con2': 0, 'con3': 0, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 0, 'con1': 1, 'con2': 0, 'con3': 0, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 1, 'con2': 0, 'con3': 0, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 0, 'con1': 0, 'con2': 1, 'con3': 0, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 0, 'con2': 1, 'con3': 0, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 0, 'con1': 1, 'con2': 1, 'con3': 0, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 1, 'con2': 1, 'con3': 0, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 0, 'con1': 0, 'con2': 0, 'con3': 1, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 0, 'con2': 0, 'con3': 1, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 0, 'con1': 1, 'con2': 0, 'con3': 1, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 1, 'con2': 0, 'con3': 1, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 0, 'con1': 0, 'con2': 1, 'con3': 1, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 0, 'con2': 1, 'con3': 1, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 0, 'con1': 1, 'con2': 1, 'con3': 1, 'con6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp1)[{'ass1': 1, 'con1': 1, 'con2': 1, 'con3': 1, 'con6': 1}] = [0.3, 0.3, 0.4]
#
diag.cpt(imp2)[{'ass1': 0, 'ass2': 0, 'con1': 0, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 1, 'ass2': 0, 'con1': 0, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 0, 'ass2': 1, 'con1': 0, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 1, 'ass2': 1, 'con1': 0, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 0, 'ass2': 0, 'con1': 1, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 1, 'ass2': 0, 'con1': 1, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 0, 'ass2': 1, 'con1': 1, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 1, 'ass2': 1, 'con1': 1, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 0, 'ass2': 0, 'con1': 0, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 1, 'ass2': 0, 'con1': 0, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 0, 'ass2': 1, 'con1': 0, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 1, 'ass2': 1, 'con1': 0, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 0, 'ass2': 0, 'con1': 1, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 1, 'ass2': 0, 'con1': 1, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 0, 'ass2': 1, 'con1': 1, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp2)[{'ass1': 1, 'ass2': 1, 'con1': 1, 'con4': 1}] = [0.3, 0.3, 0.4]
#
diag.cpt(imp3)[{'ass2': 0, 'con2': 0, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp3)[{'ass2': 1, 'con2': 0, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp3)[{'ass2': 0, 'con2': 1, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp3)[{'ass2': 1, 'con2': 1, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp3)[{'ass2': 0, 'con2': 0, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp3)[{'ass2': 1, 'con2': 0, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp3)[{'ass2': 0, 'con2': 1, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp3)[{'ass2': 1, 'con2': 1, 'con4': 1}] = [0.3, 0.3, 0.4]

diag.cpt(imp5)[{'con3': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp5)[{'con3': 1}] = [0.3, 0.3, 0.4]

diag.cpt(imp6)[{'con2': 0, 'con3': 0, 'con4': 0, 'con5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 1, 'con3': 0, 'con4': 0, 'con5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 0, 'con3': 1, 'con4': 0, 'con5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 1, 'con3': 1, 'con4': 0, 'con5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 0, 'con3': 0, 'con4': 1, 'con5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 1, 'con3': 0, 'con4': 1, 'con5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 0, 'con3': 1, 'con4': 1, 'con5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 1, 'con3': 1, 'con4': 1, 'con5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 0, 'con3': 0, 'con4': 0, 'con5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 1, 'con3': 0, 'con4': 0, 'con5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 0, 'con3': 1, 'con4': 0, 'con5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 1, 'con3': 1, 'con4': 0, 'con5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 0, 'con3': 0, 'con4': 1, 'con5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 1, 'con3': 0, 'con4': 1, 'con5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 0, 'con3': 1, 'con4': 1, 'con5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp6)[{'con2': 1, 'con3': 1, 'con4': 1, 'con5': 1}] = [0.3, 0.3, 0.4]

diag.cpt(imp7)[{'ass1': 0, 'ass2': 0, 'con1': 0, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 1, 'ass2': 0, 'con1': 0, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 0, 'ass2': 1, 'con1': 0, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 1, 'ass2': 1, 'con1': 0, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 0, 'ass2': 0, 'con1': 1, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 1, 'ass2': 0, 'con1': 1, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 0, 'ass2': 1, 'con1': 1, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 1, 'ass2': 1, 'con1': 1, 'con4': 0}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 0, 'ass2': 0, 'con1': 0, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 1, 'ass2': 0, 'con1': 0, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 0, 'ass2': 1, 'con1': 0, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 1, 'ass2': 1, 'con1': 0, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 0, 'ass2': 0, 'con1': 1, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 1, 'ass2': 0, 'con1': 1, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 0, 'ass2': 1, 'con1': 1, 'con4': 1}] = [0.3, 0.3, 0.4]
diag.cpt(imp7)[{'ass1': 1, 'ass2': 1, 'con1': 1, 'con4': 1}] = [0.3, 0.3, 0.4]

diag.cpt(obj1)[{'imp1': 0, 'imp2': 0, 'imp3': 0}] = [0.4, 0.2, 0.4]
diag.cpt(obj1)[{'imp1': 1, 'imp2': 0, 'imp3': 0}] = [0.2, 0.4, 0.4]
diag.cpt(obj1)[{'imp1': 2, 'imp2': 0, 'imp3': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 0, 'imp2': 1, 'imp3': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 1, 'imp2': 1, 'imp3': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 2, 'imp2': 1, 'imp3': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 0, 'imp2': 2, 'imp3': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 1, 'imp2': 2, 'imp3': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 2, 'imp2': 2, 'imp3': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 0, 'imp2': 0, 'imp3': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 1, 'imp2': 0, 'imp3': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 2, 'imp2': 0, 'imp3': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 0, 'imp2': 1, 'imp3': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 1, 'imp2': 1, 'imp3': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 2, 'imp2': 1, 'imp3': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 0, 'imp2': 2, 'imp3': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 1, 'imp2': 2, 'imp3': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 2, 'imp2': 2, 'imp3': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 0, 'imp2': 0, 'imp3': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 1, 'imp2': 0, 'imp3': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 2, 'imp2': 0, 'imp3': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 0, 'imp2': 1, 'imp3': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 1, 'imp2': 1, 'imp3': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 2, 'imp2': 1, 'imp3': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 0, 'imp2': 2, 'imp3': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 1, 'imp2': 2, 'imp3': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj1)[{'imp1': 2, 'imp2': 2, 'imp3': 2}] = [0.3, 0.3, 0.4]

diag.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 0, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 0, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 0, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 0, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 0, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 0, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 0, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 0, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 0, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 1, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 1, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 1, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 1, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 1, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 1, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 1, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 1, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 1, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 2, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 2, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 2, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 2, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 2, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 2, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 2, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 2, 'imp5': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 2, 'imp5': 0}] = [0.3, 0.3, 0.4]

diag.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 0, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 0, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 0, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 0, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 0, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 0, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 0, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 0, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 0, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 1, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 1, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 1, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 1, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 1, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 1, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 1, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 1, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 1, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 2, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 2, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 2, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 2, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 2, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 2, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 2, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 2, 'imp5': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 2, 'imp5': 1}] = [0.3, 0.3, 0.4]

diag.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 0, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 0, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 0, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 0, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 0, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 0, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 0, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 0, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 0, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 1, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 1, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 1, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 1, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 1, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 1, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 1, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 1, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 1, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 0, 'imp3': 2, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 0, 'imp3': 2, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 0, 'imp3': 2, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 1, 'imp3': 2, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 1, 'imp3': 2, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 1, 'imp3': 2, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 0, 'imp2': 2, 'imp3': 2, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 1, 'imp2': 2, 'imp3': 2, 'imp5': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj2)[{'imp1': 2, 'imp2': 2, 'imp3': 2, 'imp5': 2}] = [0.3, 0.3, 0.4]

diag.cpt(obj3)[{'imp1': 0, 'imp2': 0, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 0, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 0, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 1, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 1, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 1, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 2, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 2, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 2, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 0, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 0, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 0, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 1, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 1, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 1, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 2, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 2, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 2, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 0, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 0, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 0, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 1, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 1, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 1, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 2, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 2, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 2, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]

diag.cpt(obj3)[{'imp1': 0, 'imp2': 0, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 0, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 0, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 1, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 1, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 1, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 2, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 2, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 2, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 0, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 0, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 0, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 1, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 1, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 1, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 2, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 2, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 2, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 0, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 0, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 0, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 1, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 1, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 1, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 2, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 2, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 2, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]

diag.cpt(obj3)[{'imp1': 0, 'imp2': 0, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 0, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 0, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 1, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 1, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 1, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 2, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 2, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 2, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 0, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 0, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 0, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 1, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 1, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 1, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 2, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 2, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 2, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 0, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 0, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 0, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 1, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 1, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 1, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 0, 'imp2': 2, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 1, 'imp2': 2, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj3)[{'imp1': 2, 'imp2': 2, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]

diag.cpt(obj4)[{'imp1': 0, 'imp2': 0, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 0, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 0, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 1, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 1, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 1, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 2, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 2, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 2, 'imp3': 0, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 0, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 0, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 0, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 1, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 1, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 1, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 2, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 2, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 2, 'imp3': 1, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 0, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 0, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 0, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 1, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 1, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 1, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 2, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 2, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 2, 'imp3': 2, 'imp6': 0}] = [0.3, 0.3, 0.4]

diag.cpt(obj4)[{'imp1': 0, 'imp2': 0, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 0, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 0, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 1, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 1, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 1, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 2, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 2, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 2, 'imp3': 0, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 0, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 0, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 0, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 1, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 1, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 1, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 2, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 2, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 2, 'imp3': 1, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 0, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 0, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 0, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 1, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 1, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 1, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 2, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 2, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 2, 'imp3': 2, 'imp6': 1}] = [0.3, 0.3, 0.4]

diag.cpt(obj4)[{'imp1': 0, 'imp2': 0, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 0, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 0, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 1, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 1, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 1, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 2, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 2, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 2, 'imp3': 0, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 0, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 0, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 0, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 1, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 1, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 1, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 2, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 2, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 2, 'imp3': 1, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 0, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 0, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 0, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 1, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 1, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 1, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 0, 'imp2': 2, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 1, 'imp2': 2, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj4)[{'imp1': 2, 'imp2': 2, 'imp3': 2, 'imp6': 2}] = [0.3, 0.3, 0.4]


diag.cpt(obj5)[{'imp5': 0, 'imp6': 0, 'imp7': 0}] = [0.5, 0.3, 0.2]
diag.cpt(obj5)[{'imp5': 1, 'imp6': 0, 'imp7': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 2, 'imp6': 0, 'imp7': 0}] = [0.5, 0.3, 0.2]
diag.cpt(obj5)[{'imp5': 0, 'imp6': 1, 'imp7': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 1, 'imp6': 1, 'imp7': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 2, 'imp6': 1, 'imp7': 0}] = [0.1, 0.5, 0.4]
diag.cpt(obj5)[{'imp5': 0, 'imp6': 2, 'imp7': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 1, 'imp6': 2, 'imp7': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 2, 'imp6': 2, 'imp7': 0}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 0, 'imp6': 0, 'imp7': 1}] = [0.1, 0.5, 0.4]
diag.cpt(obj5)[{'imp5': 1, 'imp6': 0, 'imp7': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 2, 'imp6': 0, 'imp7': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 0, 'imp6': 1, 'imp7': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 1, 'imp6': 1, 'imp7': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 2, 'imp6': 1, 'imp7': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 0, 'imp6': 2, 'imp7': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 1, 'imp6': 2, 'imp7': 1}] = [0.2, 0.4, 0.4]
diag.cpt(obj5)[{'imp5': 2, 'imp6': 2, 'imp7': 1}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 0, 'imp6': 0, 'imp7': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 1, 'imp6': 0, 'imp7': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 2, 'imp6': 0, 'imp7': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 0, 'imp6': 1, 'imp7': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 1, 'imp6': 1, 'imp7': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 2, 'imp6': 1, 'imp7': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 0, 'imp6': 2, 'imp7': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 1, 'imp6': 2, 'imp7': 2}] = [0.3, 0.3, 0.4]
diag.cpt(obj5)[{'imp5': 2, 'imp6': 2, 'imp7': 2}] = [0.3, 0.3, 0.4]

diag.utility(util1)[{'obj1': 0, 'obj2': 0, 'obj3': 0}] = [-3]
diag.utility(util1)[{'obj1': 1, 'obj2': 0, 'obj3': 0}] = [-8]
diag.utility(util1)[{'obj1': 2, 'obj2': 0, 'obj3': 0}] = [-11]
diag.utility(util1)[{'obj1': 0, 'obj2': 1, 'obj3': 0}] = [-8]
diag.utility(util1)[{'obj1': 1, 'obj2': 1, 'obj3': 0}] = [-13]
diag.utility(util1)[{'obj1': 2, 'obj2': 1, 'obj3': 0}] = [-16]
diag.utility(util1)[{'obj1': 0, 'obj2': 2, 'obj3': 0}] = [-11]
diag.utility(util1)[{'obj1': 1, 'obj2': 2, 'obj3': 0}] = [-16]
diag.utility(util1)[{'obj1': 2, 'obj2': 2, 'obj3': 0}] = [-19]
diag.utility(util1)[{'obj1': 0, 'obj2': 0, 'obj3': 1}] = [-1]
diag.utility(util1)[{'obj1': 1, 'obj2': 0, 'obj3': 1}] = [-4]
diag.utility(util1)[{'obj1': 2, 'obj2': 0, 'obj3': 1}] = [-6]
diag.utility(util1)[{'obj1': 0, 'obj2': 1, 'obj3': 1}] = [-12]
diag.utility(util1)[{'obj1': 1, 'obj2': 1, 'obj3': 1}] = [-54]
diag.utility(util1)[{'obj1': 2, 'obj2': 1, 'obj3': 1}] = [-43]
diag.utility(util1)[{'obj1': 0, 'obj2': 2, 'obj3': 1}] = [-34]
diag.utility(util1)[{'obj1': 1, 'obj2': 2, 'obj3': 1}] = [-4]
diag.utility(util1)[{'obj1': 2, 'obj2': 2, 'obj3': 1}] = [-23]
diag.utility(util1)[{'obj1': 0, 'obj2': 0, 'obj3': 2}] = [-19]
diag.utility(util1)[{'obj1': 1, 'obj2': 0, 'obj3': 2}] = [-15]
diag.utility(util1)[{'obj1': 2, 'obj2': 0, 'obj3': 2}] = [-12]
diag.utility(util1)[{'obj1': 0, 'obj2': 1, 'obj3': 2}] = [-4]
diag.utility(util1)[{'obj1': 1, 'obj2': 1, 'obj3': 2}] = [-23]
diag.utility(util1)[{'obj1': 2, 'obj2': 1, 'obj3': 2}] = [-23]
diag.utility(util1)[{'obj1': 0, 'obj2': 2, 'obj3': 2}] = [-1]
diag.utility(util1)[{'obj1': 1, 'obj2': 2, 'obj3': 2}] = [-2]
diag.utility(util1)[{'obj1': 2, 'obj2': 2, 'obj3': 2}] = [-12]
# print(os.path.join("out", "WaterSprinkler.bif"))
diag.saveBIFXML(os.path.join("out", "Gira1.bifxml"))
# gum.saveID(diag, os.path.join("out", "Gira1.bifxml"))
#
# gum.saveID(diag, os.path.join("out", "Gira1.net"))

# Print Graph
# with open(os.path.join("out", "Gira1.bifxml"), "r") as out:
#     print(out.read())

ie = gum.ShaferShenoyLIMIDInference(diag)
ie.addNoForgettingAssumption(["re1", "ass1" ,"ass2"])
# ie.addNoForgettingAssumption(["re1", "ass2"])
# ie.addNoForgettingAssumption(["ass1", "ass2"])
# print("Is this solvable =" +str(ie.isSolvable()))
ie.addEvidence(te1, 1)
ie.addEvidence(re1, 0)
# ie.addEvidence(con1,1)
# ie.addEvidence(con2,1)
# ie.addEvidence(con3,1)
ie.makeInference()

# print(ie.optimalDecision("re1"))
# print(ie.optimalDecision("ass1"))
# print(ie.optimalDecision("ass2"))
# print("----------------------------------")
#
# print(ie.posterior(obj1).tolist())
# print(ie.posterior(obj2).tolist())
# print(ie.posterior(obj2))
# print(ie.posterior(imp2))
# print(ie.posterior(mat1))
# print(ie.posterior(mat2))
# print(ie.posterior(con1))
# print(ie.posterior(con2))
# print(ie.posterior(con3))
# print(ie.posterior("imp1"))
# print(ie.posterior(obj5))
# print(ie.posteriorUtility(util1).tolist())
# print(ie.posteriorUtility(util1))
# print(ie.posteriorUtility(util2))
# gum.ShaferShenoyLIMIDInference
