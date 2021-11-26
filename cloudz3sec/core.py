from enum import Enum
from typing import Any, Dict
import z3
from cloudz3sec.errors import InvalidValueError, InvalidCharacterError, InvalidStringTupleStructure, \
     InvalidStringTupleData, MissingStringTupleData, InvalidPolicyStructure, MissingPolicyField, MissingStringEnumData, \
         MissingStringReData, InvalidPolicyFieldType


RESERVED_CHARS = set('.',)


class BaseRe(object):
    """
    The base class for all classes equpied with z3 regular expressions.
    """
    
    def to_re(self, value=None):
        raise NotImplementedError()

    def set_data(self, value):
        """
        Set the data for the instance.
        Override this method in child classes for more complex types/behavior.
        """
        self.data = value


class StringEnumRe(BaseRe):
    """
    Base class for working with types that are restricted to a set of valid strings.

    Examples include the 
        * Action type, which is an HTTP verb and can take values like "GET", "POST", "PUT", "DELETE", ...
        * Types from the application domain which are pre-determined finite lists, e.g., "sites", "tenants", "services", etc.

    """
    
    def __init__(self, values: list[str]):
        """
        `values` - the allowable string values
        """
        for v in values:
            for c in RESERVED_CHARS:
                if c in v:
                    msg = f'The character {c} is reserved and cannot be used; it was used in {v}.'
                    raise InvalidCharacterError(message=msg)
        self.values = values
        self.z_all_vals_re_ref = z3.Union([z3.Re(z3.StringVal(v)) for v in values])
    
    def to_re(self, value=None):
        if not value:
            if hasattr(self, 'data'):
                value = self.data
            else:
                raise MissingStringEnumData('No value passed to to_re() and no data on instance. Was set_data called()?')
        if value == '*':
            return self.z_all_vals_re_ref
        if value not in self.values:
            message=f"value {value} is not allowed for type {type(self)}; allowed values are {self.values}"
            raise InvalidValueError(message=message)
        return z3.Re(z3.StringVal(value))


class StringRe(BaseRe):
    """
    Base class for working with types that are strings that allow a full character set.
    Example: path, username
    """
    
    def __init__(self, charset: set[chr]) -> None:
        """
        `charset` - the set of allowable characters for this type.
        """
        if charset.intersection(RESERVED_CHARS):
            raise InvalidCharacterError(f'The provided charset includes a reserved character and cannot be used.')
        self.charset = charset
        self.z_all_vals_re_ref = z3.Star(z3.Union([z3.Re(z3.StringVal(c)) for c in charset]))
    
    def to_re(self, value=None):
        if not value:
            if hasattr(self, 'data'):
                value = self.data
            else:
                raise MissingStringReData('No value passed to to_re() and no data on instance. Was set_data called()?')
        if value == '*':
            return self.z_all_vals_re_ref
        if not '*' in value:
            return z3.Re(z3.StringVal(value))
        parts = value.split('*')
        # compute the first one since Concat requires at least two args.
        result = z3.Concat(z3.Re(z3.StringVal(parts[0])), self.z_all_vals_re_ref)
        # handle the case of str containing a single * in the last char
        if len(parts) == 2 and value[-1] == '*':
            return result
        for idx, part in enumerate(parts[1:]):
            # it is possible the str ends in a '*', in which case we only need to add a single re_all_chars,
            # unless we already did because this is the
            if part == '':
                if idx == 0:
                    return result
                return z3.Concat(result, self.z_all_vals_re_ref)
            # handle whether this is the final part or not:
            if idx + 2 == len(parts):
                return z3.Concat(result, z3.Re(z3.StringVal(part)))
            result = z3.Concat(result, z3.Re(z3.StringVal(part)))
        return result

 
class StringTupleRe(BaseRe):
    """
    Base class for working with types that are tuples of string types.  
    """

    def __init__(self, fields: list[Dict[str, Any]]) -> None:
        for f in fields:
            if not 'name' in f:
                raise InvalidStringTupleStructure(message=f'field {f} missing required "name" key.')
            if not type(f['name']) == str:
                raise InvalidStringTupleStructure(message=f'field {f} "name" property should be type string.')
            if not 'type' in f:
                raise InvalidStringTupleStructure(message=f'field {f} missing required "type" key.')
            if not type(f['type']) == type:
                raise InvalidStringTupleStructure(message=f'field {f} "type" property should be type Type.')
            # create an instance of f['type'] passing the **f['kwargs'] as the key-word arguments to the constructor.
            val = f['type'](**f['kwargs'])
            setattr(self, f['name'], val)
            
        self.fields = fields
        self.field_names = [f['name'] for f in self.fields]
        self.data = {}

    def to_re(self):
        if not self.data:
            raise MissingStringTupleData(f'No data found on {type(self)} object; was set_data() called?')
        res = []
        for idx, field in enumerate(self.fields):
            value = self.data[field['name']]
            res.append(field['type'].to_re(getattr(self, field['name']), value))
            # separate each field in the tuple with a dot ('.') character, but not after the very last field:
            if idx < len(self.fields)-1:
                res.append(z3.Re(z3.StringVal('.')))
        return z3.Concat(*res)

    def set_data(self, **kwargs):
        for k, v in kwargs.items():
            if k not in self.field_names:
                raise InvalidStringTupleData(message=f'Got unexpected argument {k} to set_data(). Fields are: {self.field_names}')
            self.data[k] = v
        # check that all fields were set
        for f in self.field_names:
            if f not in self.data.keys():
                raise InvalidStringTupleData(message=f'Required field {f} missing in call to set_data.')


class Decision(object):
    """
    A class representing a decision in a policy. 
    In the current implementation, every Policy must have exactly one decision field.
    """
    def __init__(self, decision: str) -> None:
        if not decision in ['allow', 'deny']:
            raise InvalidValueError(f'Decisions must have value allow or deny; got {decision}.')
        self.decision = decision


class BasePolicy(object):
    """
    Base class for working with policies. Decend from this class and specify the fields for your policy engine.
    """
    def __init__(self, fields: list[Dict[str, Any]], **kwargs) -> None:
        # every policy is currently required to have exactly one decision field, because the decision property is critical to the
        # current implementation of the policy equivalence checker.
        found_decision = False
        # we want to track the fields that are not the decision field, as these will be analyzed together by the policy equivalence checker
        not_decision_fields = []
        for f in fields:
            if not 'name' in f:
                raise InvalidPolicyStructure(message=f'field {f} missing required "name" key.')
            if not type(f['name']) == str:
                raise InvalidPolicyStructure(message=f'field {f} "name" property should be type string.')
            if not 'type' in f:
                raise InvalidPolicyStructure(message=f'field {f} missing required "type" key.')
            if not type(f['type']) == type:
                raise InvalidPolicyStructure(message=f'field {f} "type" property should be type Type.')
            # create an attribute on the policy for each field defined. 
            property = f['name']
            prop_type = f['type']
            if prop_type == Decision:
                # if we already found a Decision, this is the 2nd one and that is an error.
                if found_decision:
                    raise InvalidPolicyStructure(message=f'A property can have only one Decision field; found 2 or more.')
                found_decision = True
                self.decision_field = property
            else:
                not_decision_fields.append(f)
            if not property in kwargs.keys():
                raise MissingPolicyField(message=f'Policy requires the {property} parameter. Found: {kwargs.keys()}')
            if not type(kwargs[property]) == prop_type:
                raise InvalidPolicyFieldType(message=f'field {property} must be of type {prop_type}; got {type(kwargs[property])}.')
            setattr(self, property, kwargs[property])
        # todo -- decide about this
        # if we did not find a decision, we can either raise an error or add one automatically. for now, we will raise an error
        if not found_decision:
            raise InvalidPolicyStructure(message='A policy class is required to have exactly one Deciion field; and did not find one.')
        self.all_fields = fields
        self.fields = not_decision_fields
        self.field_names = [f['name'] for f in self.fields]        
        

class PolicyEquivalenceChecker(object):
    """
    Class for reasoning formally about two sets of policies.
    """
    
    def __init__(self, policy_type: type, policy_set_p: list[BasePolicy], policy_set_q: list[BasePolicy]):
        # the type of policies this policy checker is working with. Should be a child of BasePolicy
        self.policy_type = policy_type
        
        # the two sets of policies
        self.policy_set_p = policy_set_p
        self.policy_set_q = policy_set_q
        
        # one free string variable for each dimensions of a policy
        self.free_variables = {}
        for f in self.policy_type.fields:
            # the Decision field is special and is a dimension of the equations
            if f['type'] == Decision:
                continue
            prop_name = f['name']
            self.free_variables[prop_name] = z3.String(prop_name)

        # statements related to the policy sets (1 for each)
        self.P, self.Q = self.get_statements()

    def get_allow_policies(self, policy_set: list[BasePolicy]):
        return [p for p in policy_set if getattr(p, p.decision_field).decision == 'allow']
    
    def get_deny_policies(self, policy_set: list[BasePolicy]):
        return [p for p in policy_set if getattr(p, p.decision_field).decision == 'deny']
    
    def get_match_list(self, policy_set: list[BasePolicy]):
        and_list = []
        for p in policy_set:
            and_re = [z3.InRe(self.free_variables[f], getattr(p, f).to_re()) for f in self.free_variables.keys() ]
            and_list.append(z3.And(*and_re))
        return and_list

    def get_policy_set_re(self, allow_match_list: list, deny_match_list: list):
        if len(deny_match_list) == 0:
            return z3.Or(*deny_match_list)
        else:
            return z3.And(z3.Or(*allow_match_list), z3.Not(z3.And(*deny_match_list)))

    def get_statements(self):
        for p_set in [self.policy_set_p, self.policy_set_q]:
            allow_match_list = self.get_match_list(self.get_allow_policies(p_set))
            deny_match_list = self.get_match_list(self.get_deny_policies(p_set))
            yield self.get_policy_set_re(allow_match_list, deny_match_list)

    def prove(self, statement_1, statement_2):
        return z3.prove(z3.Implies(statement_1, statement_2))

    def p_implies_q(self):
        return self.prove(self.P, self.Q)

    def q_implies_p(self):
        return self.prove(self.Q, self.P)
