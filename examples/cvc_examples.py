import sys
#sys.path.append('/home/cloudcvcsec')
sys.path.append('/Users/spadhy/Documents/z3prover/z3/cloudcvcsec')

# print(f"python path: {sys.path}")
import cvc5
from cloudcvcsec.cvc_cloud import CloudPolicy, CloudExamplePolicy,CloudPolicyManager
from cloudcvcsec.cvc_core import PolicyEquivalenceChecker



slv1 = cvc5.Solver()
# Set the logic
slv1.setLogic("ALL")
# Produce models
slv1.setOption("produce-models", "true")
# The option strings-exp is needed
slv1.setOption("strings-exp", "true")
# Set output language to SMTLIB2
slv1.setOption("output-language", "smt2")
slv1.setOption("produce-unsat-cores", "true")
t1 = CloudPolicyManager()
# example 1:
print("\n -------------------------- Start of Example 1 ------------------- \n ")
# In this example, policy set 1 is more permissive than set 2, as it allows any method on sys1:
p1 = t1.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys1', '*', 'allow',slv1)
p2 = t1.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys2', '*', 'deny', slv1)
p = [p1, p2]
q1 = t1.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys1', 'GET', 'allow',slv1)
q2 = t1.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys2', 'GET', 'deny', slv1)
q = [q1, q2]
chk_1 = PolicyEquivalenceChecker(policy_type=CloudPolicy, policy_set_p=p, policy_set_q=q, slv=slv1)
print("\n ------------ Result Example 1 -------- \n ")
# cvc5 proves that the Q policy set is less permissive than P:
chk_1.q_implies_p()
# proved
print(" q => p: Expected: UNSAT and Proved")
#
# and it finds a counter example when we ask it to prove that P => Q:
chk_1.p_implies_q()
print(" p => q: Expected: SAT and CounterExample")
# counterexample
# [action = "PUT",
#  resource = "tacc.dev.systems./sys1",
#  principal = "tacc.dev.testuser1"]
print("\n ---------------------------End of Example 1 ---------------------- \n ")
print("\n -------------------------- Start of Example 2 ------------------- \n ")
slv2 = cvc5.Solver()
# Set the logic
slv2.setLogic("ALL")
# Produce models
slv2.setOption("produce-models", "true")
# The option strings-exp is needed
slv2.setOption("strings-exp", "true")
# Set output language to SMTLIB2
slv2.setOption("output-language", "smt2")
slv2.setOption("produce-unsat-cores", "true")
t2 = CloudPolicyManager()
# example 2:
# In this example, the two policy sets are incomparable (note the required trailing slash in p1),
# and cvc5 finds counter examples for each implication.
p1 = t2.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys1/*', '*', 'allow',slv2)
p2 = t2.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys2', '*', 'deny',slv2)
p = [p1, p2]

q1 = t2.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys1', 'GET', 'allow',slv2)
q2 = t2.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys2', 'GET', 'deny',slv2)
q = [q1, q2]
chk_2 = PolicyEquivalenceChecker(policy_type=CloudPolicy, policy_set_p=p, policy_set_q=q, slv=slv2)

print("\n ---------- Result Example 2 -------- \n ")
chk_2.p_implies_q()
# counterexample
# [resource = "tacc.dev.systems./sys1/",
#  action = "POST",
#  principal = "tacc.dev.testuser1"]
#
print(" p => q : Expected: SAT and CounterExample")
chk_2.q_implies_p()
# counterexample
# [action = "GET",
# resource = "tacc.dev.systems./sys1",
# principal = "tacc.dev.testuser1"]

print(" q => p: Expected: SAT and CounterExample")
print("\n --------------------------- End of Example 2 --------------------\n ")

print("\n -------------------------- Start of Example 3 ------------------- \n ")


slv3 = cvc5.Solver()
# Set the logic
slv3.setLogic("ALL")
# Produce models
slv3.setOption("produce-models", "true")
# The option strings-exp is needed
slv3.setOption("strings-exp", "true")
# Set output language to SMTLIB2
slv3.setOption("output-language", "smt2")
slv3.setOption("produce-unsat-cores", "true")
t3 = CloudPolicyManager()
# example 3:
# In this example, policy set P is striclty less permissive that policy set Q,
# as P allows GETs on paths /sys1/* while Q allows all GETs.
p1 = t3.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.files./sys1/*', 'GET', 'allow',slv3)
p2 = t3.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.files./sys2/*', 'GET', 'deny',slv3)
p6 = [p1, p2]

q1 = t3.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.files./*', 'GET', 'allow',slv3)
q2 = t3.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.files./sys2/*', 'GET', 'deny',slv3)
q6 = [q1, q2]
chk_3 = PolicyEquivalenceChecker(policy_type=CloudPolicy, policy_set_p=p6, policy_set_q=q6, slv=slv3)


print("\n --------- Result Example 3 ---------- \n ")
# In this case, z3 can find a counter example to Q => P
chk_3.q_implies_p()
print(" q => p : Expected: SAT and CounterExample ")
# counterexample
# [resource = "tacc.dev.files./",
# action = "GET",
# principal = "tacc.dev.testuser1"]

# However, in this case z3 gets stuck trying to prove that P => Q
chk_3.p_implies_q()
print(" p => q: Expected: UNSAT and Proved")

print("\n ----------------------------- End of Example 3 -------------------\n ")


