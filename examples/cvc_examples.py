import sys
#sys.path.append('/home/cloudz3sec')
sys.path.append('/Users/spadhy/Documents/z3prover/z3/cloudz3sec')
# print(f"python path: {sys.path}")
import cvc5
from cloudz3sec.cvc_cloud import CloudPolicy, CloudExamplePolicy,CloudPolicyManager
from cloudz3sec.cvc_core import PolicyEquivalenceChecker



slv = cvc5.Solver()
# Set the logic
slv.setLogic("ALL")
# Produce models
slv.setOption("produce-models", "true")
# The option strings-exp is needed
slv.setOption("strings-exp", "true")
# Set output language to SMTLIB2
slv.setOption("output-language", "smt2")

# convenience instance for creating policies
t = CloudPolicyManager()


print("\n policy p1: \n ")
p1 = t.policy_from_strs('tacc.dev.testuser1', 'allow', slv)
print("\n policy p2: \n ")
p2 = t.policy_from_strs('tacc.dev.testuser2', 'deny', slv)
p = [p1, p2]


print("\n policy q1: \n ")
q1 = t.policy_from_strs('tacc.dev.testuser1','allow', slv)
print("\n policy q2: \n ")
q2 = t.policy_from_strs('tacc.dev.testuser2',  'deny',slv)
q = [q1, q2]
#chk_0 = PolicyEquivalenceChecker(policy_type=CloudExamplePolicy, policy_set_p=p, policy_set_q=q, slv=slv)
#print("\n Result Example 0 -------- \n ")
#chk_0.q_implies_p()
#chk_0.p_implies_q()
# create two sets of policies, p and q


slv1 = cvc5.Solver()
# Set the logic
slv1.setLogic("ALL")
# Produce models
slv1.setOption("produce-models", "true")
# The option strings-exp is needed
slv1.setOption("strings-exp", "true")
# Set output language to SMTLIB2
slv1.setOption("output-language", "smt2")
t1 = CloudPolicyManager()
# example 1:
# In this example, policy set 1 is more permissive than set 2, as it allows any method on sys1:
print("\n policy p0: \n ")
p0 = t1.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.systems./sys', '*', 'allow',slv1)
print("\n policy p1: \n ")
p1 = t1.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.systems./sys1', '*', 'allow',slv1)
print("\n policy p2: \n ")
p2 = t1.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.systems./sys2', '*', 'deny', slv1)
print("\n policy p3: \n ")
p3 = t1.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.systems./sys2', '*', 'deny', slv1)
p = [p0, p1, p2,p3]

print("\n policy q0: \n ")
q0 = t1.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.systems./sys', '*', 'allow',slv1)
print("\n policy q1: \n ")
q1 = t1.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.systems./sys1', 'GET', 'allow',slv1)
print("\n policy q2: \n ")
q2 = t1.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.systems./sys2', 'GET', 'deny', slv1)
print("\n policy q3: \n ")
q3 = t1.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.systems./sys2', '*', 'deny', slv1)

q = [q0,q1, q2,q3]
chk_1 = PolicyEquivalenceChecker(policy_type=CloudPolicy, policy_set_p=p, policy_set_q=q, slv=slv1)
print("\n Result Example 1 -------- \n ")
# z3 proves that the Q policy set is less permissive than P:
chk_1.q_implies_p()
# proved
#
# and it finds a counter example when we ask it to prove that P => Q:
chk_1.p_implies_q()
# counterexample
# [action = "PUT",
#  resource = "tacc.dev.systems./sys1",
#  principal = "tacc.dev.testuser1"]



slv2 = cvc5.Solver()
# Set the logic
slv2.setLogic("ALL")
# Produce models
slv2.setOption("produce-models", "true")
# The option strings-exp is needed
slv2.setOption("strings-exp", "true")
# Set output language to SMTLIB2
slv2.setOption("output-language", "smt2")
t2 = CloudPolicyManager()
# example 2:
# In this example, the two policy sets are incomparable (note the required trailing slash in p1),
# and z3 finds counter examples for each implication.
p1 = t2.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.systems./sys1/*', '*', 'allow',slv2)
p2 = t2.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.systems./sys2', '*', 'deny',slv2)
p = [p1, p2]

q1 = t2.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.systems./sys1', 'GET', 'allow',slv2)
q2 = t2.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.systems./sys2', 'GET', 'deny',slv2)
q = [q1, q2]
chk_2 = PolicyEquivalenceChecker(policy_type=CloudPolicy, policy_set_p=p, policy_set_q=q, slv=slv2)

print("\n Result Example 2 -------- \n ")
chk_2.p_implies_q()
# counterexample
# [resource = "tacc.dev.systems./sys1/",
#  action = "POST",
#  principal = "tacc.dev.testuser1"]
#
chk_2.q_implies_p()
# counterexample
# [action = "GET",
# resource = "tacc.dev.systems./sys1",
# principal = "tacc.dev.testuser1"]



slv = cvc5.Solver()
# Set the logic
slv.setLogic("ALL")
# Produce models
slv.setOption("produce-models", "true")
# The option strings-exp is needed
slv.setOption("strings-exp", "true")
# Set output language to SMTLIB2
slv.setOption("output-language", "smt2")

t = CloudPolicyManager()
# example 3:
# In this example, policy set P is striclty less permissive that policy set Q,
# as P allows GETs on paths /sys1/* while Q allows all GETs.
p1 = t.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.files./sys1/*', 'GET', 'allow',slv)
p2 = t.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.files./sys2/*', 'GET', 'deny',slv)
p = [p1, p2]

q1 = t.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.files./*', 'GET', 'allow',slv)
q2 = t.policy_from_strs1('tacc.dev.testuser1', 'tacc.dev.files./sys2/*', 'GET', 'deny',slv)
q = [q1, q2]
chk_3 = PolicyEquivalenceChecker(policy_type=CloudPolicy, policy_set_p=p, policy_set_q=q, slv=slv)


print("\n Result Example 3 -------- \n ")
# In this case, z3 can find a counter example to Q => P
chk_3.q_implies_p()
# counterexample
# [resource = "tacc.dev.files./",
# action = "GET",
# principal = "tacc.dev.testuser1"]

# However, in this case z3 gets stuck trying to prove that P => Q
chk_3.p_implies_q()
# (... hangs ....)