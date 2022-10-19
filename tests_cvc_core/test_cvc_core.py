import os
import pytest
import sys

# add the current working directory to the python path so that the tests can run easily from
# within the tests Docker container
sys.path.append(os.path.curdir)
print(f"Python path: {sys.path}")

#import z3
import cvc5
from cvc5 import Kind, Term, Solver
from cloudcvcsec import cvc_core, cvc_cloud, errors

def get_solver():
    slv = cvc5.Solver()
    # Set the logic
    slv.setLogic("ALL")
    # Produce models
    slv.setOption("produce-models", "true")
    # The option strings-exp is needed
    slv.setOption("strings-exp", "true")
    # Set output language to SMTLIB2
    slv.setOption("output-language", "smt2")
    slv.setOption("produce-unsat-cores", "true")
    return slv

def get_simple_string_enum_re(slv):
    # possible values for the enum --
    values = ['val_1', 'val_2', 'val_3']
    # construct an enum with the possible values.
    three_vals_enum = cvc_core.StringEnumRe(values=values, slv=slv)
    return three_vals_enum


def test_string_enum_re_basic():

    slv = get_solver()
    # the three_vals_enum object represents the universe of possible instances of the enum.
    three_vals_enum = get_simple_string_enum_re(slv)
    # we can provide it a specific value using set_data
    three_vals_enum.set_data(value='val_1')
    # the to_re method generates a z3 regular expression based on the value we set.
    regex = three_vals_enum.to_re()
    #assert regex == z3.Re(z3.StringVal('val_1'))
    assert regex == slv.mkTerm(Kind.STRING_TO_REGEXP,slv.mkString('val_1'))
    # only 'val_1' should match
    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('val_1'), regex))
    assert not sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('val_2'), regex))


def sat_term(slv,term):
    result = slv.checkSatAssuming(term)
    if result.isSat() == True:
        return True
    return False

def test_string_enum_re_wildcard():
    slv = get_solver()
    # the three_vals_enum object represents the universe of possible instances of the enum.
    three_vals_enum = get_simple_string_enum_re(slv)
    # we can provide it a wildcard as a specific value
    three_vals_enum.set_data(value='*')
    # the to_re method generates a z3 regular expression based on the value we set.
    regex = three_vals_enum.to_re()
    # all three values should match
    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('val_1'), regex))
    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('val_2'), regex))
    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('val_3'), regex))

    # but a value not in the enum won't
    assert not sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('foo'), regex))

def test_string_enum_re_invalid():
    slv = get_solver()
    # the three_vals_enum object represents the universe of possible instances of the enum.
    three_vals_enum = get_simple_string_enum_re(slv)
    # we cannot provide a value that isn't on the list.
    three_vals_enum.set_data(value='foo')
    with pytest.raises(errors.InvalidValueError):
        three_vals_enum.to_re()
    # for enums, only an isolated wildcard is allowed; mixing wildcard and static string is not supported
    three_vals_enum.set_data(value='val*')
    with pytest.raises(errors.InvalidValueError):
        three_vals_enum.to_re()


def get_simple_string_re(slv):
    # when initially contstructing the StringRe, we only provide data about the universe of allowable
    # strings; i.e., the character set
    chars_string_re = cvc_core.StringRe(charset=cvc_cloud.ALPHANUM_SET, slv=slv)
    return chars_string_re


def test_string_re_basic():
    slv = get_solver()
    s = get_simple_string_re(slv)
    # we can provide a specific value using the set_data --
    s.set_data('foobar')
    # we use the to_re method to generate a z3 regular expression based on this value.
    regex = s.to_re()
    # since we provided a static string, that is the only one that will match --
    # anything else will not match
    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('foobar'), regex))
    assert not sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('fooba'), regex))
    assert not sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('oobar'), regex))
    assert not sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('foobr'), regex))



def test_string_re_wildcard():
    slv = get_solver()
    s = get_simple_string_re(slv)
    # we can provide a specific value with a wildcard --
    s.set_data('foo*')
    # we use the to_re method to generate a z3 regular expression based on this value.
    regex = s.to_re()
    # now, any string beginning with foo will match
    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('foo'), regex))
    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('foobar'), regex))
    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('foo12345aaaaaaaaaaa'), regex))

    # but strings not beginning with "foo" will not match
    assert not sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('fobo'), regex))
    assert not sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('oobar'), regex))
    assert not sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('fo0'), regex))


def test_string_re_invalid():
    slv = get_solver()
    s = get_simple_string_re(slv)
    # the charset of ALPHANUM_SET restricts what characters we can use:
    s.set_data('not_valid/')
    with pytest.raises(errors.InvalidValueError):
        s.to_re()


def get_simple_string_tuple_re(slv):
    # StringTupleRe's are useful for types that are made up of multiple StringRe or StringEnumRe objects
    # but that get treated as a single "field" when specifying security policies. For example, a
    # "name" field might be tuple of "first_name" and "last_name". Another example might be an "endpoint"
    # in an HTTP API, where the "endpoint" is made up of a "url_path" (StringRe) and an HTTP verb
    # (StringEnum).
    # like the other types, instantiation involves specifying the universe of possible value for the
    # StringTupleRe. this means specifying all of the fields, their types, and all arguments to the
    # contructors for those types.
    fields = [
        {
            'name': 'verb',
            'type': cvc_core.StringEnumRe,
            'kwargs': {'values': ['GET', 'POST', 'PUT', 'DELETE'], 'slv': slv}

        },
        {
            'name': 'url_path',
            'type': cvc_core.StringRe,
            'kwargs': {'charset': cvc_cloud.PATH_CHAR_SET, 'slv': slv}
        }
    ]
    s = cvc_core.StringTupleRe(fields=fields, slv=slv)
    return s


def test_string_tuple_re_basic():
    slv = get_solver()
    s = get_simple_string_tuple_re(slv)
    # the set_data on a StringTupleRe expects arguments whose names are the same as the names of the fields
    # making up the StringTupleRe and whose values are the values to the corresponding set_data for the
    # field type.
    s.set_data(url_path='/sprokets/123', verb='GET')
    # just as with the other types, the StringTupleRe's to_re() method converts the specific value (which
    # must have previously been set with set_data(..)) to a z3 regex:
    regex = s.to_re()
    # for matching purposes, the StringTupleRe type creates a single variable by concatinating each of its
    # fields, separating them with the reserved '.' character. The order of the fields is important, as this
    # is the order they are concatinated.
    # since our specific data contained only static strings (no wild cards) we expect only exact matches:

    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('GET./sprokets/123'), regex))
    assert not sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('POST./sprokets/123'), regex))
    assert not sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('GET./sprokets/12'), regex))


def test_string_tuple_re_wildcard():
    slv = get_solver()
    s = get_simple_string_tuple_re(slv)
    # when setting data on a StringTupleRe, we can use wildcards in the individual fields just like if
    # we had variables of the specific type.
    s.set_data(url_path='/sprokets*', verb='*')
    regex = s.to_re()
    # now, any path that begins with "/sprokets" should match and verb from the set defined abouve
    # should match.
    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('GET./sprokets/123'), regex))
    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('POST./sprokets'), regex))
    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('PUT./sprokets/1234/details'), regex))

    # however, if any individual component doesn't match, the whole InRe will be false:

    assert not sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('GET./sprok'), regex))
    # HEAD isn't in the list
    assert not sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('HEAD./sprok'), regex))


def test_string_tuple_re_invalid():
    slv = get_solver()
    s = get_simple_string_tuple_re(slv)
    # first, we must supply all variables to set_data or else InvalidStringTupleData is raise
    with pytest.raises(errors.InvalidStringTupleData):
        s.set_data(url_path='/foo')
    # if we try to set invalid data, an error will be raised when to_re() is invoked.
    s.set_data(url_path='/foo/^&', verb='GET')
    # here url_path is not contained in the allowable charset
    with pytest.raises(errors.InvalidValueError):
        s.to_re()
    # similarly, if we try to set an invalid verb
    s.set_data(url_path='/foo', verb='HEAD')
    with pytest.raises(errors.InvalidValueError):
        s.to_re()


# we'll define two types to create our policy class with ----
class User(cvc_core.StringTupleRe):
    # here we define a class User representing a user in a cloud system. It has two fields: the "username"
    # field is a StringRe that can be made up of any characters from the ALPHANUM_SET char set.
    # the second field is the "tenant" field; it is a StringEnum field, the assumption being the value
    # for the tenant is one of a finite list. In this case, the User type allows for the list of
    # allowable tenants to be passed in when constructing the User object.
    def __init__(self, tenants, slv):
        fields = [
            {'name': 'username', 'type': cvc_core.StringRe, 'kwargs': {'charset': cvc_cloud.ALPHANUM_SET, 'slv':slv}},
            {'name': 'tenant', 'type': cvc_core.StringEnumRe, 'kwargs': {'values': tenants, 'slv':slv}}
        ]
        super().__init__(fields, slv)


# the second class in our policy will represent an endpoint within an API. It has two fields as well: the
# verb and the url_path in the endpoint. note that unlike in the User case where we allowed the set of
# allowable tenants to be passed in at construction time, here we specify the fixed set of values for the
# HTTP verb. this is a matter of choice and meeting whatever requirements we have for the application.
class Endpoint(cvc_core.StringTupleRe):
    def __init__(self, slv):
        fields = [
            {'name': 'verb', 'type': cvc_core.StringEnumRe, 'kwargs': {'values': ['GET', 'POST', 'PUT', 'DELETE'], 'slv':slv}},
            {'name': 'url_path', 'type': cvc_core.StringRe, 'kwargs': {'charset': cvc_cloud.PATH_CHAR_SET, 'slv':slv}},
        ]
        super().__init__(fields, slv)


def get_simple_base_policy(slv):
    # a BasePolicy object represents a type of security policy. It is specified by specifying the
    # fields that make up the policy. Each field must have a name and a type.
    # It is also a requirement that exactly one field be a cvc_core.Decision type. The Decision field is a
    # special type that can only take the values "allow" or "deny".

    # here are the fields making up the actual policy ---
    fields = [
        {
            'name': 'user',
            'type': User,
        },
        {
            'name': 'endpoint',
            'type': Endpoint,
        },
        {
            'name': 'decision',
            'type': cvc_core.Decision
        }

    ]

    # we will create a User, Endpoint and Decision for our policy. Keep in mind that the User
    # and Endpoint objects collectively represent an entity (or collection of entities) that we wish to
    # allow or deny access to, so we can include wildcards.
    # Keep in mind that when constructing the fields, we only provide data to specify the "universe" of
    # allowable values. For User, that is the tenants list:
    user = User(tenants=['test', 'alpha', 'beta', 'prod'], slv = slv)
    # like before, we use set_data() to actually set the specific value for this policy.
    user.set_data(username='*', tenant='test')
    # for Endpoint, the universe was fully set in the class definition, so we have nothing to specify to
    # the constructor.
    endpoint = Endpoint(slv=slv)
    # here we set the url_path and verb, both include wildcards.
    endpoint.set_data(url_path='/foo/*', verb='*')
    # the Decison type works slightly differently; simply specify the value with the constructor.
    decision = cvc_core.Decision('allow')
    # when creating a BasePolicy, we must specify the fields and a kwarg for each named field.
    # the values for the field names should be of that type.
    policy = cvc_core.BasePolicy(fields=fields, user=user, endpoint=endpoint, decision=decision)
    return policy


def test_base_policy_basic():

    slv = get_solver()
    policy = get_simple_base_policy(slv)
    # the policy object itself is mostly just a container for the types and values it holds; it doesn't
    # do much extra, but we can still use the methods on the individual fields in the policy.
    assert hasattr(policy, 'user')
    assert hasattr(policy, 'endpoint')
    assert hasattr(policy, 'decision')
    assert type(policy.user) == User
    assert type(policy.endpoint) == Endpoint
    assert type(policy.decision) == cvc_core.Decision
    # note that policy.user is a User (i.e., is a StringTupleRe) for which set_data() has already been run,
    # so we can call to_re() on it directly and compare it using z3.
    # jsmith.test will be in the re because the policy set a wildcard for username.

    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('jsmth.test'), policy.user.to_re()))
    # however, jsmith.beta will not be because the policy set a specific tenant of "test"

    assert not sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('jsmth.beta'), policy.user.to_re()))
    # similarly for our endpoint
    # any verb with any path beginning with /foo/ will match
    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('GET./foo/bar'), policy.endpoint.to_re()))
    assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('POST./foo/baz/123'), policy.endpoint.to_re()))
    assert not sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('GET./fo1'), policy.endpoint.to_re()))


def test_basic_policy_invalid():
    # there are lots of ways to make invalid policies. The simplest is to not provide a decision field.
    fields = [
        {
            'name': 'user',
            'type': User,
        },
        {
            'name': 'endpoint',
            'type': Endpoint,
        }
    ]
    slv = get_solver()
    user = User(tenants=['test', 'alpha', 'beta', 'prod'], slv=slv)
    user.set_data(username='*', tenant='test')
    endpoint = Endpoint(slv)
    endpoint.set_data(url_path='/foo/*', verb='*')
    with pytest.raises(errors.InvalidPolicyStructure):
        policy = cvc_core.BasePolicy(fields=fields, user=user, endpoint=endpoint)
    # let's add the decision field so we get past that error:
    fields.append({'name': 'decision', 'type': cvc_core.Decision})
    decision = cvc_core.Decision('allow')
    # let's create a new User object and not call set_data
    user = User(tenants=['test', 'alpha', 'beta', 'prod'], slv=slv)
    # we can create the policy just fine
    policy = cvc_core.BasePolicy(fields=fields, user=user, endpoint=endpoint, decision=decision)
    # but now we cannot use the to_re() method on the user field. if we try to, we'll get a
    # MissingStringTupleData error --
    with pytest.raises(errors.MissingStringTupleData):
        assert sat_term(slv, slv.mkTerm(Kind.STRING_IN_REGEXP, slv.mkString('jsmth.test'), policy.user.to_re()))



class SimplePolicy(cvc_core.BasePolicy):
    # a class representing a simple policy.
    # we just specify the fields --
    fields = [
        {
            'name': 'user',
            'type': User,
        },
        {
            'name': 'endpoint',
            'type': Endpoint,
        },
        {
            'name': 'decision',
            'type': cvc_core.Decision
        }
    ]

    # we have to call super() and set the fields we want above.
    def __init__(self, **kwargs):
        super().__init__(fields=SimplePolicy.fields, **kwargs)


def get_simple_policy_lists(slv):

    # we'll make two policy lists that each have just one policy in them.
    # to construct a policy, we need to construct the invidividual fields in the policy.
    user1 = User(tenants=['test', 'alpha', 'beta', 'prod'], slv=slv)
    user1.set_data(username='*', tenant='test')
    endpoint1 = Endpoint(slv)
    endpoint1.set_data(verb='*', url_path='/apps')
    decision1 = cvc_core.Decision('allow')
    p1 = SimplePolicy(user=user1, endpoint=endpoint1, decision=decision1)

    user2 = User(tenants=['test', 'alpha', 'beta', 'prod'], slv= slv)
    user2.set_data(username='jstubbs', tenant='test')
    endpoint1 = Endpoint(slv)
    endpoint1.set_data(verb='*', url_path='/apps')
    decision1 = cvc_core.Decision('allow')
    p2 = SimplePolicy(user=user2, endpoint=endpoint1, decision=decision1)
    return [p1], [p2]


def get_simple_policy_equiv_checker(slv):

    # the PolicyEquivalenceChecker class allows use of z3 to formally analyze the equivalence of two
    # policy sets.
    # it requires two lists of policies, with both lists containing policies of a single type.
    p_list_1, p_list_2 = get_simple_policy_lists(slv)
    checker = cvc_core.PolicyEquivalenceChecker(policy_type=SimplePolicy,
                                            policy_set_p=p_list_1,
                                            policy_set_q=p_list_2, slv=slv)

    return checker


def test_simple_policy_checker_counter_ex(capsys):
    slv = get_solver()
    checker = get_simple_policy_equiv_checker(slv)
    # we can use the checker to check if the policy sets are equivalent. We know p_list_1 is strictly
    # more permissive than p_list_2.
    # this prints "counterexample"
    checker.p_implies_q()
    # use capsys to capture stdout; cf., https://docs.pytest.org/en/6.2.x/capture.html
    captured = capsys.readouterr()
    print(capsys.readouterr())
    assert 'counterexample' in captured.out


def test_simple_policy_checker_proved(capsys):
    slv = get_solver()
    checker = get_simple_policy_equiv_checker(slv)
    # we can use the checker to check if the policy sets are equivalent. We know p_list_1 is strictly
    # more permissive than p_list_2.
    # this prints "proved"
    checker.q_implies_p()
    # use capsys to capture stdout; cf., https://docs.pytest.org/en/6.2.x/capture.html
    captured = capsys.readouterr()
    capsys.readouterr()
    assert 'PROVED' in captured.out


def test_simple_policy_checker_internals():
    slv = get_solver()
    # the policy checker has a number of helper methods for computing the equivalence of the policy lists.
    checker = get_simple_policy_equiv_checker(slv)
    # first, it contains a set of free z3 variables for each of its fields EXCEPT for the Decision field.
    # NOTE: we are removing the free_variables object
    # assert len(checker.free_variables) == len(checker.policy_type.fields) - 1
    # the free_variables object is a dictionary, with keys equal to the names of the fields in the
    # Policy (except for the Decision field)
    # assert 'user' in checker.free_variables.keys()
    # assert 'endpoint' in checker.free_variables.keys()
    # # each free variable is a z3.String('...') variable
    # assert type(checker.free_variables['user']) == z3.z3.SeqRef == type(z3.String('abc'))
    # assert type(checker.free_variables['endpoint']) == z3.z3.SeqRef == type(z3.String('abc'))

    assert len(checker.cvc_constraint_property_names) == len(checker.policy_type.fields) - 1


