import os
import pytest
import sys

# add the current working directory to the python path so that the tests can run easily from
# within the tests Docker container
sys.path.append(os.path.curdir)
print(f"Python path: {sys.path}")

import z3

from cloudz3sec import core, cloud, errors


def get_simple_string_enum_re():
    # possible values for the enum --
    values = ['val_1', 'val_2', 'val_3']    
    # construct an enum with the possible values. 
    three_vals_enum = core.StringEnumRe(values=values)
    return three_vals_enum    


def test_string_enum_re_basic():
    # the three_vals_enum object represents the universe of possible instances of the enum.
    three_vals_enum = get_simple_string_enum_re()
    # we can provide it a specific value using set_data
    three_vals_enum.set_data(value='val_1')
    # the to_re method generates a z3 regular expression based on the value we set.
    regex = three_vals_enum.to_re()
    assert regex == z3.Re(z3.StringVal('val_1'))
    # only 'val_1' should match
    assert z3.simplify(z3.InRe('val_1', regex))
    assert not z3.simplify(z3.InRe('val_2', regex))


def test_string_enum_re_wildcard():
    # the three_vals_enum object represents the universe of possible instances of the enum.
    three_vals_enum = get_simple_string_enum_re()
    # we can provide it a wildcard as a specific value
    three_vals_enum.set_data(value='*')
    # the to_re method generates a z3 regular expression based on the value we set.
    regex = three_vals_enum.to_re()
    # all three values should match
    assert z3.simplify(z3.InRe('val_1', regex))
    assert z3.simplify(z3.InRe('val_2', regex))
    assert z3.simplify(z3.InRe('val_3', regex))
    # but a value not in the enum won't
    assert not z3.simplify(z3.InRe('foo', regex))


def test_string_enum_re_invalid():
    # the three_vals_enum object represents the universe of possible instances of the enum.
    three_vals_enum = get_simple_string_enum_re()
    # we cannot provide a value that isn't on the list.
    three_vals_enum.set_data(value='foo')
    with pytest.raises(errors.InvalidValueError): 
        three_vals_enum.to_re()
    # for enums, only an isolated wildcard is allowed; mixing wildcard and static string is not supported
    three_vals_enum.set_data(value='val*')
    with pytest.raises(errors.InvalidValueError): 
        three_vals_enum.to_re()
    

def get_simple_string_re():
    # when initially contstructing the StringRe, we only provide data about the universe of allowable 
    # strings; i.e., the character set
    chars_string_re = core.StringRe(charset=cloud.ALPHANUM_SET)
    return chars_string_re


def test_string_re_basic():
    s = get_simple_string_re()
    # we can provide a specific value using the set_data --
    s.set_data('foobar')
    # we use the to_re method to generate a z3 regular expression based on this value.
    regex = s.to_re()
    # since we provided a static string, that is the only one that will match --
    assert z3.simplify(z3.InRe('foobar', regex))
    # anything else will not match
    assert not z3.simplify(z3.InRe('fooba', regex))
    assert not z3.simplify(z3.InRe('oobar', regex))
    assert not z3.simplify(z3.InRe('foobr', regex))


def test_string_re_wildcard():
    s = get_simple_string_re()
    # we can provide a specific value with a wildcard --
    s.set_data('foo*')
    # we use the to_re method to generate a z3 regular expression based on this value.
    regex = s.to_re()
    # now, any string beginning with foo will match
    assert z3.simplify(z3.InRe('foo', regex))
    assert z3.simplify(z3.InRe('foobar', regex))
    assert z3.simplify(z3.InRe('foo12345aaaaaaaaaaa', regex))
    # but strings not beginning with "foo" will not match
    assert not z3.simplify(z3.InRe('fobo', regex))
    assert not z3.simplify(z3.InRe('oobar', regex))
    assert not z3.simplify(z3.InRe('fo0', regex))


def test_string_re_invalid():
    s = get_simple_string_re()
    # the charset of ALPHANUM_SET restricts what characters we can use:
    s.set_data('not_valid/')
    with pytest.raises(errors.InvalidValueError): 
        s.to_re()


def get_simple_string_tuple_re():
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
            'type': core.StringEnumRe,
            'kwargs': {'values': ['GET', 'POST', 'PUT', 'DELETE']}

        },
        {
            'name': 'url_path',
            'type': core.StringRe,
            'kwargs': {'charset': cloud.PATH_CHAR_SET}
        }
    ]
    s = core.StringTupleRe(fields=fields)
    return s


def test_string_tuple_re_basic():
    s = get_simple_string_tuple_re()
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
    assert z3.simplify(z3.InRe('GET./sprokets/123', regex))
    assert not z3.simplify(z3.InRe('POST./sprokets/123', regex))
    assert not z3.simplify(z3.InRe('GET./sprokets/12', regex))


def test_string_tuple_re_wildcard():
    s = get_simple_string_tuple_re()
    # when setting data on a StringTupleRe, we can use wildcards in the individual fields just like if 
    # we had variables of the specific type.
    s.set_data(url_path='/sprokets*', verb='*')
    regex = s.to_re()
    # now, any path that begins with "/sprokets" should match and verb from the set defined abouve 
    # should match.
    assert z3.simplify(z3.InRe('GET./sprokets/123', regex))
    assert z3.simplify(z3.InRe('POST./sprokets', regex))
    assert z3.simplify(z3.InRe('PUT./sprokets/1234/details', regex))
    # however, if any individual component doesn't match, the whole InRe will be false:
    assert not z3.simplify(z3.InRe('GET./sprok', regex))
    # HEAD isn't in the list
    assert not z3.simplify(z3.InRe('HEAD./sprokets', regex))


def test_string_tuple_re_invalid():
    s = get_simple_string_tuple_re()
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


def get_simple_ip_addr():
    return core.IpAddr2(netmasklen=24)


def test_ip_addr_basic():
    ip_addr = get_simple_ip_addr()
    ip_addr.set_data('11.22.33.0')
    assert ip_addr.ip_bv == z3.Concat(z3.BitVecVal('11',8),z3.BitVecVal('22',8),z3.BitVecVal('33',8),z3.BitVecVal('0',8))


# we'll define two types to create our policy class with ----  
class User(core.StringTupleRe):
    # here we define a class User representing a user in a cloud system. It has two fields: the "username"
    # field is a StringRe that can be made up of any characters from the ALPHANUM_SET char set.
    # the second field is the "tenant" field; it is a StringEnum field, the assumption being the value
    # for the tenant is one of a finite list. In this case, the User type allows for the list of 
    # allowable tenants to be passed in when constructing the User object.
    def __init__(self, tenants):
        fields = [
            {'name': 'username', 'type': core.StringRe, 'kwargs': {'charset': cloud.ALPHANUM_SET}},
            {'name': 'tenant', 'type': core.StringEnumRe, 'kwargs': {'values': tenants}}
        ]
        super().__init__(fields)

# the second class in our policy will represent an endpoint within an API. It has two fields as well: the
# verb and the url_path in the endpoint. note that unlike in the User case where we allowed the set of
# allowable tenants to be passed in at construction time, here we specify the fixed set of values for the 
# HTTP verb. this is a matter of choice and meeting whatever requirements we have for the application.
class Endpoint(core.StringTupleRe):
    def __init__(self):
        fields = [
            {'name': 'verb', 'type': core.StringEnumRe, 'kwargs': {'values': ['GET', 'POST', 'PUT', 'DELETE']}},
            {'name': 'url_path', 'type': core.StringRe, 'kwargs': {'charset': cloud.PATH_CHAR_SET}},
        ]
        super().__init__(fields)


def get_simple_base_policy():
    # a BasePolicy object represents a type of security policy. It is specified by specifying the
    # fields that make up the policy. Each field must have a name and a type.
    # It is also a requirement that exactly one field be a core.Decision type. The Decision field is a 
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
            'type': core.Decision
        }

    ]
    # we will create a User, Endpoint and Decision for our policy. Keep in mind that the User 
    # and Endpoint objects collectively represent an entity (or collection of entities) that we wish to 
    # allow or deny access to, so we can include wildcards.
    # Keep in mind that when constructing the fields, we only provide data to specify the "universe" of 
    # allowable values. For User, that is the tenants list:
    user = User(tenants=['test', 'alpha', 'beta', 'prod'])
    # like before, we use set_data() to actually set the specific value for this policy.
    user.set_data(username='*', tenant='test')
    # for Endpoint, the universe was fully set in the class definition, so we have nothing to specify to
    # the constructor.
    endpoint = Endpoint()
    # here we set the url_path and verb, both include wildcards.
    endpoint.set_data(url_path='/foo/*', verb='*')
    # the Decison type works slightly differently; simply specify the value with the constructor.
    decision = core.Decision('allow')
    # when creating a BasePolicy, we must specify the fields and a kwarg for each named field.
    # the values for the field names should be of that type.
    policy = core.BasePolicy(fields=fields, user=user, endpoint=endpoint, decision=decision)
    return policy


def test_base_policy_basic():
    policy = get_simple_base_policy()
    # the policy object itself is mostly just a container for the types and values it holds; it doesn't
    # do much extra, but we can still use the methods on the individual fields in the policy.
    assert hasattr(policy, 'user')
    assert hasattr(policy, 'endpoint')
    assert hasattr(policy, 'decision')
    assert type(policy.user) == User
    assert type(policy.endpoint) == Endpoint
    assert type(policy.decision) == core.Decision
    # note that policy.user is a User (i.e., is a StringTupleRe) for which set_data() has already been run, 
    # so we can call to_re() on it directly and compare it using z3.
    # jsmith.test will be in the re because the policy set a wildcard for username.
    assert z3.simplify(z3.InRe('jsmth.test', policy.user.to_re()))
    # however, jsmith.beta will not be because the policy set a specific tenant of "test"
    assert not z3.simplify(z3.InRe('jsmth.beta', policy.user.to_re()))
    # similarly for our endpoint
    # any verb with any path beginning with /foo/ will match 
    assert z3.simplify(z3.InRe('GET./foo/bar', policy.endpoint.to_re()))
    assert z3.simplify(z3.InRe('POST./foo/baz/123', policy.endpoint.to_re()))
    assert not z3.simplify(z3.InRe('GET./fo1', policy.endpoint.to_re()))


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
    user = User(tenants=['test', 'alpha', 'beta', 'prod'])
    user.set_data(username='*', tenant='test')
    endpoint = Endpoint()
    endpoint.set_data(url_path='/foo/*', verb='*')
    with pytest.raises(errors.InvalidPolicyStructure):
        policy = core.BasePolicy(fields=fields, user=user, endpoint=endpoint)
    # let's add the decision field so we get past that error:
    fields.append({'name': 'decision', 'type': core.Decision})
    decision = core.Decision('allow')
    # let's create a new User object and not call set_data
    user = User(tenants=['test', 'alpha', 'beta', 'prod'])
    # we can create the policy just fine
    policy = core.BasePolicy(fields=fields, user=user, endpoint=endpoint, decision=decision)
    # but now we cannot use the to_re() method on the user field. if we try to, we'll get a 
    # MissingStringTupleData error --
    with pytest.raises(errors.MissingStringTupleData):
        assert z3.simplify(z3.InRe('jsmth.test', policy.user.to_re()))


class SimplePolicy(core.BasePolicy):
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
            'type': core.Decision
        }
    ]
    # we have to call super() and set the fields we want above.
    def __init__(self, **kwargs):
        super().__init__(fields=SimplePolicy.fields, **kwargs)


def get_simple_policy_lists():
    # we'll make two policy lists that each have just one policy in them.
    # to construct a policy, we need to construct the invidividual fields in the policy.
    user1 = User(tenants=['test', 'alpha', 'beta', 'prod'])
    user1.set_data(username='*', tenant='test')
    endpoint1 = Endpoint()
    endpoint1.set_data(verb='*', url_path='/apps')
    decision1 = core.Decision('allow')
    p1 = SimplePolicy(user=user1, endpoint=endpoint1, decision=decision1)

    user2 = User(tenants=['test', 'alpha', 'beta', 'prod'])
    user2.set_data(username='jstubbs', tenant='test')
    endpoint1 = Endpoint()
    endpoint1.set_data(verb='*', url_path='/apps')
    decision1 = core.Decision('allow')
    p2 = SimplePolicy(user=user2, endpoint=endpoint1, decision=decision1)
    return [p1], [p2]


def get_simple_policy_equiv_checker():
    # the PolicyEquivalenceChecker class allows use of z3 to formally analyze the equivalence of two
    # policy sets.
    # it requires two lists of policies, with both lists containing policies of a single type.
    p_list_1, p_list_2 = get_simple_policy_lists()
    checker = core.PolicyEquivalenceChecker(policy_type=SimplePolicy, 
                                            policy_set_p=p_list_1, 
                                            policy_set_q=p_list_2)

    return checker


def test_simple_policy_checker_counter_ex(capsys):
    checker = get_simple_policy_equiv_checker()
    # we can use the checker to check if the policy sets are equivalent. We know p_list_1 is strictly
    # more permissive than p_list_2.
    # this prints "counterexample"
    checker.p_implies_q()
    # use capsys to capture stdout; cf., https://docs.pytest.org/en/6.2.x/capture.html
    captured = capsys.readouterr()
    print(capsys.readouterr())
    assert 'counterexample' in captured.out


def test_simple_policy_checker_proved(capsys):
    checker = get_simple_policy_equiv_checker()
    # we can use the checker to check if the policy sets are equivalent. We know p_list_1 is strictly
    # more permissive than p_list_2.
    # this prints "proved"
    checker.q_implies_p()
    # use capsys to capture stdout; cf., https://docs.pytest.org/en/6.2.x/capture.html
    captured = capsys.readouterr()
    capsys.readouterr()
    assert 'proved' in captured.out


def test_simple_policy_checker_internals():
    # the policy checker has a number of helper methods for computing the equivalence of the policy lists.
    checker = get_simple_policy_equiv_checker()
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
    
    assert len(checker.z3_constraint_property_names) == len(checker.policy_type.fields) - 1


# Example Firewall Policy
#Name	Enabled	Action	Local Port	Remote Address	Remote Port	Protocol
#Foo1	Yes	Allow	100	10.3.141.0	100	UDP
class FirewallPolicy(core.BasePolicy):
    # a class representing a firewall policy.
    # we just specify the fields --
    fields = [
        {
            'name': 'remote_address',
            'type': core.IpAddr2,
        },
        {
            'name': 'protocol',
            'type': core.StringEnumRe,
            'kwargs': {'values': ['UDP','TCP']}
        },
        {
            'name': 'decision',
            'type': core.Decision
        }
    ]
    # we have to call super() and set the fields we want above.
    def __init__(self, **kwargs):
        super().__init__(fields=FirewallPolicy.fields, **kwargs)

def get_firewall_policy_lists():
    # we'll make two policy lists that each have just one policy in them.
    # to construct a policy, we need to construct the invidividual fields in the policy.

    remote_ipaddr1 = core.IpAddr2(netmasklen=24)
    remote_ipaddr1.set_data('11.22.33.0')
    decision1 = core.Decision('allow')

    proto1 = core.StringEnumRe(values=['TCP','UDP'])
    proto1.set_data(value='TCP')
    p1 = FirewallPolicy(remote_address=remote_ipaddr1, protocol=proto1, decision=decision1)

    remote_ipaddr2 = core.IpAddr2(netmasklen=16)
    remote_ipaddr2.set_data('11.22.0.0')
    proto2 = core.StringEnumRe(values=['TCP', 'UDP'])
    proto2.set_data(value='TCP')
    decision2 = core.Decision('allow')
    p2 = FirewallPolicy(remote_address=remote_ipaddr2, protocol=proto2, decision=decision2)

    return [p1], [p2]

def get_firewall_policy_equiv_checker():
    # the PolicyEquivalenceChecker class allows use of z3 to formally analyze the equivalence of two
    # policy sets.
    # it requires two lists of policies, with both lists containing policies of a single type.
    p_list_1, p_list_2 = get_firewall_policy_lists()
    checker = core.PolicyEquivalenceChecker(policy_type=FirewallPolicy,
                                            policy_set_p=p_list_1,
                                            policy_set_q=p_list_2)

    return checker

def test_firwall_policy_checker_proved(capsys):
    checker = get_firewall_policy_equiv_checker()
    # we can use the checker to check if the policy sets are equivalent. We know p_list_1 is strictly
    # less permissive than p_list_2.
    # this prints "proved"
    checker.p_implies_q()
    # use capsys to capture stdout; cf., https://docs.pytest.org/en/6.2.x/capture.html
    captured = capsys.readouterr()
    print(capsys.readouterr())
    assert 'proved' in captured.out


def test_firewall_policy_checker_counter_ex(capsys):
    checker = get_firewall_policy_equiv_checker()
    # we can use the checker to check if the policy sets are equivalent. We know p_list_1 is strictly
    # more permissive than p_list_2.
    # this prints "counterexample"
    checker.q_implies_p()
    # use capsys to capture stdout; cf., https://docs.pytest.org/en/6.2.x/capture.html
    captured = capsys.readouterr()
    capsys.readouterr()
    assert 'counterexample' in captured.out