import os

from z3.z3 import Q
import pytest
import sys

# add the current working directory to the python path so that the tests can run easily from
# within the tests Docker container
sys.path.append(os.path.curdir)
print(f"Python path: {sys.path}")

from cloudz3sec import cloud, core


class DynamicEnum(core.StringEnumRe):
    """
    An enum class that includes a list of possible values from 1 to N.
    """
    def __init__(self, N: int) -> None:
        values = [str(i) for i in range(N)]
        super().__init__(values=values)


class DynamicEnumPolicy(core.BasePolicy):
    fields = [
        {'name': 'de', 'type': DynamicEnum},
        {'name': 'decision', 'type': core.Decision}
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(fields=DynamicEnumPolicy.fields, **kwargs)    


def test_enum_scale(capsys):
    """
    In this test, we check the scalability of the policy checker with an enum that takes on a larger and larger
    set of possible values. 
    """
    # Ballpark performance numbers (run on a core i9 vPRO)
    # note that 10,000 values seems to induce a major slowdown.
    # 100   -- test runs in 1.69 seconds; 
    # 1,000 -- test runs in 16.91 seconds
    # 10,000 -- should be 169 + 16.9 ~= 187 (or 3 minutes, 7 seconds.) but instead it took 2036.68s (almost 34 minutes)
    
    # Uncomment one of the following to run tests for certain sizes ---------
    # for n in [10, 100, 1000, 10000]: 
    # for n in [10, 100, 1000]:
    for n in [10]: # n denotes the number of allowable values in the StringEnum
    # -----------------------------------------------------------------------
        policy_p = []
        en = DynamicEnum(N=n)
        for i in range(n):
            # create a policy allowing each possible value:
            en.set_data(str(i))
            dp = DynamicEnumPolicy(de=en, decision=core.Decision('allow'))
            policy_p.append(dp)
        
        # create a single policy with a wildcard for the enum
        en.set_data("*")
        policy_q = [DynamicEnumPolicy(de=en, decision=core.Decision('allow'))]
        # create the policy checker for both of these
        chk = core.PolicyEquivalenceChecker(policy_type=DynamicEnumPolicy, policy_set_p=policy_p, policy_set_q=policy_q)
        chk.p_implies_q()
        chk.q_implies_p()        
        captured = capsys.readouterr()
        capsys.readouterr()
        # the string "proved" should appear exactly twice in the stdout, once for each of p_implies_q() and q_implies_p()
        assert 2 == captured.out.count('proved')


class DynamicTuple(core.StringTupleRe):
    
    def __init__(self, num_fields: int, num_enum_vals: int):
        fields = [{'name': f'field_{i}', 'type': DynamicEnum, 'kwargs': {'N': num_enum_vals}} for i in range(num_fields)]
        super().__init__(fields=fields)


class DynamicTuplePolicy(core.BasePolicy):
    fields = [
        {'name': 'tup', 'type': DynamicTuple},
        {'name': 'decision', 'type': core.Decision}
    ]
    
    def __init__(self, **kwargs) -> None:
        super().__init__(fields=DynamicTuplePolicy.fields, **kwargs)    


def test_tuple_scale(capsys):
    """
    In this test, we check the scalability of the policy checker with a tuple which takes on more and more fields.
    """
    # NOTE: we are not currently, but we could also vary the size of the enum
    num_eval_values = 4

    # Ballpark performance numbers (run on a core i9 vPRO)
    # 10    -- test runs in 0.71 seconds;
    # 100   -- test runs in 231.6 seconds; 
    # 1,000 -- test runs in ??? seconds
    # 10,000 -- test runs in ??? seconds

    # Uncomment one of the following to run tests for certain sizes ---------
    # for n in [10, 100, 1000, 10000]:
    # for n in [10, 100, 1000]:
    # for n in [10, 100]:
    for n in [10]: # n denotes the number of fields in the tuple.
    # -----------------------------------------------------------------------
        policy_p = []
        # for each possible eval value, create a policy where field_1 takes that value and allows any other value (*) for all 
        # other fields
        kwargs = {}
        for i in range(n):
            kwargs[f'field_{i}'] = '*'
        # override field_0 for each policy.
        for j in range(num_eval_values):
            kwargs['field_0'] = str(j)
            tup = DynamicTuple(num_fields=n, num_enum_vals=num_eval_values)
            tup.set_data(**kwargs)
            policy_p.append(DynamicTuplePolicy(tup=tup, decision=core.Decision('allow')))

        # next, create a single policy that allows any value (*) for all enum fields:
        kwargs = {}
        for i in range(n):
            kwargs[f'field_{i}'] = '*'
        tup = DynamicTuple(num_fields=n, num_enum_vals=num_eval_values)
        tup.set_data(**kwargs)
        policy_q = [DynamicTuplePolicy(tup=tup, decision=core.Decision('allow'))]
        # create the policy checker for both of these
        chk = core.PolicyEquivalenceChecker(policy_type=DynamicTuplePolicy, policy_set_p=policy_p, policy_set_q=policy_q)
        chk.p_implies_q()
        chk.q_implies_p()        
        captured = capsys.readouterr()
        capsys.readouterr()
        # the string "proved" should appear exactly twice in the stdout, once for each of p_implies_q() and q_implies_p()
        assert 2 == captured.out.count('proved')


class AlphaNumStringRe(core.StringRe):
    def __init__(self):
        super().__init__(charset=cloud.PATH_CHAR_SET)


class AlphaNumPolicy(core.BasePolicy):
    fields = [
        {'name': 'field_1', 'type': AlphaNumStringRe},
        {'name': 'decision', 'type': core.Decision}
    ]
    
    def __init__(self, **kwargs) -> None:
        super().__init__(fields=AlphaNumPolicy.fields, **kwargs)    


def test_string_re_scale(capsys):
    """
    In this test, we check the scalability of the policy checker with a stringRe that takes on a different number of values.
    """

    # Ballpark performance numbers (run on a core i9 vPRO)
    # 10    -- test runs in 0.77 seconds;
    # 100   -- test runs in 0.98 seconds; 
    # 1,000 -- test runs in 2.49 seconds;
    # 10,000 -- test runs in 16.49 seconds;
    
    # Uncomment one of the following to run tests for certain sizes ---------
    # for n in [10, 100, 1000, 10000]:
    # for n in [10, 100, 1000]:
    # for n in [10, 100]:
    for n in [10]: # n denotes the number of policies; each policy will take a different value.
    # -----------------------------------------------------------------------
        policy_p = []
        policy_q = []
        for i in range(n):
            p_val = str(i)
            q_val = str(n-i-1)
            field_1 = AlphaNumStringRe()
            field_1.set_data(p_val)
            pol = AlphaNumPolicy(field_1=field_1, decision=core.Decision('allow'))
            policy_p.append(pol)
            field_1.set_data(q_val)
            pol = AlphaNumPolicy(field_1=field_1, decision=core.Decision('allow'))
            policy_q.append(pol)

        # create the policy checker for both of these
        chk = core.PolicyEquivalenceChecker(policy_type=AlphaNumPolicy, policy_set_p=policy_p, policy_set_q=policy_q)
        chk.p_implies_q()
        chk.q_implies_p()        
        captured = capsys.readouterr()
        capsys.readouterr()
        # the string "proved" should appear exactly twice in the stdout, once for each of p_implies_q() and q_implies_p()
        assert 2 == captured.out.count('proved')


def test_string_re_wildcard_scale(capsys):
    """
    Test the scalability of the policy checker with a stringRe that takes on a different number of values.

    Note that this test only proves 1 theorem (p_implies_q(); i.e., half the number of the other tests) because the converse 
    (q_implies_p()) is false in this test case.
    """
    # Ballpark performance numbers (run on a core i9 vPRO)
    # 10    -- test runs in 0.91 seconds;
    # 100   -- test runs in 2.58 seconds; 
    # 1,000 -- test runs in 27.8 seconds;
    # 10,000 -- test runs in 3326.7 seconds (55 minutes);
    
    # Uncomment one of the following to run tests for certain sizes ---------
    # for n in [10, 100, 1000, 10000]:
    # for n in [10, 100, 1000]:
    # for n in [10, 100]:
    for n in [10]: # n denotes the number of policies; each policy will take a different value.
    # -----------------------------------------------------------------------
        policy_p = []
        policy_q = []
        for i in range(n):
            # todo -- could also vary the length of the base string
            p_val = f'a1b2c3d4e5/{i}'
            # the q policy value is the p value with a * at the end.
            q_val = f'{p_val}*'
            field_1 = AlphaNumStringRe()
            field_1.set_data(p_val)
            pol = AlphaNumPolicy(field_1=field_1, decision=core.Decision('allow'))
            policy_p.append(pol)
            field_1.set_data(q_val)
            pol = AlphaNumPolicy(field_1=field_1, decision=core.Decision('allow'))
            policy_q.append(pol)

        # create the policy checker for both of these
        chk = core.PolicyEquivalenceChecker(policy_type=AlphaNumPolicy, policy_set_p=policy_p, policy_set_q=policy_q)
        # p implies q because q contained all the strings in policies of p but with a wildcard at the end
        chk.p_implies_q()
        captured = capsys.readouterr()
        capsys.readouterr()
        # the string "proved" should appear exactly once in the stdout, since only p_implies_q() was true
        assert 1 == captured.out.count('proved')
