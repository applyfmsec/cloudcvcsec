from enum import Enum
from typing import Any, Dict
import cvc5
from cvc5 import Kind, Term, Solver
import z3
from cloudz3sec import errors
from cloudz3sec.errors import InvalidValueError, InvalidCharacterError, InvalidStringTupleStructure, \
    InvalidStringTupleData, MissingStringTupleData, InvalidPolicyStructure, MissingPolicyField, MissingStringEnumData, \
    MissingStringReData, InvalidPolicyFieldType, MissingInstanceData

# from cloudz3sec.cloudz3sec.cloud import SrcIp

RESERVED_CHARS = set('.', )


class BaseRe(object):
    """
    The base class for all classes equipped with z3 regular expressions.
    """

    def __init__(self, slv: cvc5.Solver):  #<---- Added Sover
        #print("Setting up the solver in BaseRe \n")

        self.slv = slv
        # String type
        #self.string = self.slv.getStringSort()

    def to_re(self, value=None):
        raise NotImplementedError()

    def set_data(self, value):
        """
        Set the data for the instance.
        Override this method in child classes for more complex types/behavior.
        """
        self.data = value
        #print("\n BaseRe set data =", self.data)

    #def get_cvc_boolterm(self, name: str) -> cvc5.Term:
    def get_cvc_boolterm(self, free_var: Term) -> cvc5.Term:
        """
                Generate a z3 boolean expression in one or more free variables that equals the constraint in the free variable(s)
                represented by the value specified for this instance.
                `name` - the name to use when generating the free variable(s). Typically, the `name` will be given by the name of the
                field in the policy.

                Note: this function can only be called once set_data() has been called on the instance.
        """
        if not hasattr(self, 'data') or not self.data:
            raise MissingInstanceData('No data on instance. get_cvc_bool_term requires data. Was set_data called()?')
        #print("forming cvc boolterm -->" , name)
        # String variables
        #free_var = self.slv.mkConst(self.string, name)
        term = self.slv.mkTerm(Kind.STRING_IN_REGEXP, free_var, self.to_re())
        #print(" \n term = " , term)
        return term
        #return term


class StringEnumRe(BaseRe):
    """
    Base class for working with types that are restricted to a set of valid strings.

    Examples include the
        * Action type, which is an HTTP verb and can take values like "GET", "POST", "PUT", "DELETE", ...
        * Types from the application domain which are pre-determined finite lists, e.g., "sites", "tenants", "services", etc.

    """

    def __init__(self, values: list[str], slv:cvc5.Solver): #<---- Added Sover
        """
        `values` - the allowable string values
        """
        BaseRe.__init__(self, slv)
        for v in values:
            for c in RESERVED_CHARS:
                if c in v:
                    msg = f'The character {c} is reserved and cannot be used; it was used in {v}.'
                    raise InvalidCharacterError(message=msg)
        self.values = values
        #self.z_all_vals_re_ref = z3.Union([z3.Re(z3.StringVal(v)) for v in values])
        p = [self.slv.mkTerm(Kind.STRING_TO_REGEXP,
                        self.slv.mkString(v)) for v in values]
        self.z_all_vals_re_ref = self.slv.mkTerm(Kind.REGEXP_UNION,*p)

    def to_re(self, value=None):
        if not value:
            if hasattr(self, 'data'):
                value = self.data
            else:
                raise MissingStringEnumData(
                    'No value passed to to_re() and no data on instance. Was set_data called()?')
        if value == '*':
            return self.z_all_vals_re_ref
        if value not in self.values:
            message = f"value {value} is not allowed for type {type(self)}; allowed values are {self.values}"
            raise InvalidValueError(message=message)
        #return z3.Re(z3.StringVal(value))
        #print("\n StringEnumRe = ", value)
        term = self.slv.mkTerm(Kind.STRING_TO_REGEXP,
                        self.slv.mkString(value))
        #print(" \n term = ", term)
        return term



class StringRe(BaseRe):
    """
    Base class for working with types that are strings that allow a full character set.
    Example: path, username
    """

    def __init__(self, charset: set[chr], slv:cvc5.Solver) -> None:
        """
        `charset` - the set of allowable characters for this type.
        """
        BaseRe.__init__(self, slv)
        if charset.intersection(RESERVED_CHARS):
            raise InvalidCharacterError(f'The provided charset includes a reserved character and cannot be used.')
        self.charset = charset
        #self.z_all_vals_re_ref = z3.Star(z3.Union([z3.Re(z3.StringVal(c)) for c in charset]))
        p = [self.slv.mkTerm(Kind.STRING_TO_REGEXP,
                             self.slv.mkString(c)) for c in charset]
        self.z_all_vals_re_ref = self.slv.mkTerm(Kind.REGEXP_STAR,self.slv.mkTerm(Kind.REGEXP_UNION, *p))


    def to_re(self, value=None):
        if not value:
            if hasattr(self, 'data'):
                value = self.data
            else:
                raise MissingStringReData('No value passed to to_re() and no data on instance. Was set_data called()?')
        # check that the value is contained within the charset plus the * character
        if not self.charset.union(set('*')).intersection(set(value)) == set(value):
            raise errors.InvalidValueError("Data must be contained within the charset for this StringrRe.")
        if value == '*':
            return self.z_all_vals_re_ref
        if not '*' in value:
            return self.slv.mkTerm(Kind.STRING_TO_REGEXP,
                                   self.slv.mkString(value))
            #return z3.Re(z3.StringVal(value))
        parts = value.split('*')
        # compute the first one since Concat requires at least two args.
        #result = z3.Concat(z3.Re(z3.StringVal(parts[0])), self.z_all_vals_re_ref)
        result = self.slv.mkTerm(Kind.REGEXP_CONCAT,
                    self.slv.mkTerm(Kind.STRING_TO_REGEXP,
                               self.slv.mkString(parts[0])),
                    self.z_all_vals_re_ref)
        # handle the case of str containing a single * in the last char
        if len(parts) == 2 and value[-1] == '*':
            return result
        for idx, part in enumerate(parts[1:]):
            # it is possible the str ends in a '*', in which case we only need to add a single re_all_chars,
            # unless we already did because this is the
            if part == '':
                if idx == 0:
                    return result
                #return z3.Concat(result, self.z_all_vals_re_ref)
                return self.slv.mkTerm(Kind.REGEXP_CONCAT,result, self.z_all_vals_re_ref)
            # handle whether this is the final part or not:
            if idx + 2 == len(parts):
                #return z3.Concat(result, z3.Re(z3.StringVal(part)))
                return self.slv.mkTerm(Kind.REGEXP_CONCAT,result, self.slv.mkTerm(Kind.STRING_TO_REGEXP,
                               self.slv.mkString(part)))
            #result = z3.Concat(result, z3.Re(z3.StringVal(part)))
            result = self.slv.mkTerm(Kind.REGEXP_CONCAT,result, self.slv.mkTerm(Kind.STRING_TO_REGEXP,
                               self.slv.mkString(part)))
        return result


class StringTupleRe(BaseRe):
    """
    Base class for working with types that are tuples of string types.
    """

    def __init__(self, fields: list[Dict[str, Any]], slv: cvc5.Solver) -> None: #<---- Added Sover
        BaseRe.__init__(self, slv) #<---- Added Sover
        #print("\n fields: ", fields)
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
            #print("\n val = ", val)
            setattr(self, f['name'], val)

        self.fields = fields
        self.field_names = [f['name'] for f in self.fields]
        self.data = {}

    def to_re(self) :
        if not self.data:
            raise MissingStringTupleData(f'No data found on {type(self)} object; was set_data() called?')
        res = []
        # for debugging
        i=0
        #print("\n fields: ", self.fields)
        ###
        for idx, field in enumerate(self.fields):
            value = self.data[field['name']]
            #print("\n name  = ", value, "  field = ", field)
            res.append(field['type'].to_re(getattr(self, field['name']), value))
            #### for debugging
            #if i == 0:
            #    print("\n res = ", res)
            #i = i + 1
            ####
            # separate each field in the tuple with a dot ('.') character, but not after the very last field:
            if idx < len(self.fields) - 1:
                #print ("\n size(fields) = ", len(self.fields),  " idx = ", idx)
                #res.append(z3.Re(z3.StringVal('.')))
                res.append(self.slv.mkTerm(Kind.STRING_TO_REGEXP,
                               self.slv.mkString('.')))
                #print("\n res = ", res)
            #print(res)
        #return z3.Concat(*res)
        #print("\n final res = ", res)
        #e = self.slv.mkTerm(Kind.STRING_TO_REGEXP,self.slv.mkString('tacc'))

        #e = res[0]
        term = self.slv.mkTerm(Kind.REGEXP_CONCAT, *res)
        #print("y = ", y)
        return term

        #return self.slv.mkTerm(Kind.REGEXP_CONCAT,e, p[1],p[2],p[3], p[4])

    def set_data(self, **kwargs):
        for k, v in kwargs.items():
            if k not in self.field_names:
                raise InvalidStringTupleData(
                    message=f'Got unexpected argument {k} to set_data(). Fields are: {self.field_names}')
            self.data[k] = v
        #print("\n StringTupleRe set data =", self.data)
        # check that all fields were set
        for f in self.field_names:
            if f not in self.data.keys():
                raise InvalidStringTupleData(message=f'Required field {f} missing in call to set_data.')


class IpAddr2(object):
    """
    A class representing string of the IP address in the CIDR format.
    """

    def __init__(self, netmasklen: int):
        self.slv = cvc5.Solver()
        self.slv.setLogic("QF_BV")

        self.netmasklen = netmasklen
        if self.netmasklen == 24:
            self.netmask_bv = self.convert_to_bv('255.255.255.0')
        # TODO -- is this right?
        elif self.netmasklen == 16:  # 16 bit
            self.netmask_bv = self.convert_to_bv('255.255.0.0')
        elif self.netmasklen == 8:  # 8 bit
            self.netmask_bv = self.convert_to_bv('255.0.0.0')
        else:
            raise InvalidValueError(f"Value {netmasklen} is not a supported netmaskelen. Valid values are: 8,16,24.")

    def convert_to_bv(self, ip: str):
        """
        Convert an IP address (string) to a z3 bit vector value.
        """
        parts = ip.split('.')
        if not len(parts) == 4:
            raise InvalidValueError("Invalid IP address; format must be A.B.C.D")
        # TODO -- why 8?
        # slv.mkBitVectorSort(32)
        #	mkBitVector(int size, long val)
        #addr_bit_vecs = [z3.BitVecVal(part, 8) for part in parts]
        addr_bit_vecs = [self.slv.mkBitVector(8,part) for part in parts]
        #return z3.Concat(*addr_bit_vecs)
        return self.slv.mkTerm(Kind.REGEXP_CONCAT, *addr_bit_vecs)

    def set_data(self, ip_addr: str):
        """
        Set the actual IP address for this instance.
        """
        self.ip_addr = ip_addr
        self.ip_bv = self.convert_to_bv(ip_addr)
        self.masked_ip_bv = self.ip_bv & self.netmask_bv

    def get_cvc_boolterm(self,name):
        free_vars = self.slv.mkTerm(Kind.REGEXP_CONCAT,
                                    self.slv.mkBitVectorConst(8,f'{name}_a'),
                                    self.slv.mkBitVectorConst(8, f'{name}_b'),
                                    self.slv.mkBitVectorConst(8, f'{name}_c'),
                                    self.slv.mkBitVectorConst(8, f'{name}_d'))
        return self.slv.simplify(self.slv.mkTerm(Kind.EQUAL,self.slv.simplify(self.slv.mkTerm(Kind.BITVECTOR_AND,free_vars, self.netmask_bv)),
                                                 self.masked_ip_bv))

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
            # TODO -- we could check that the value of f['type'] is one of the classes that we recognize, i.e.,
            # a StringEnumRe, StringRe, StringTupleRe, etc.

            # create an attribute on the policy for each field defined.
            property = f['name']
            prop_type = f['type']
            if prop_type == Decision:
                # if we already found a Decision, this is the 2nd one and that is an error.
                if found_decision:
                    raise InvalidPolicyStructure(
                        message=f'A property can have only one Decision field; found 2 or more.')
                found_decision = True
                self.decision_field = property
            else:
                # the field names must be unique, as the names are typically used to generate free variable names.
                # we check for uniqueness of fields here:
                if f['name'] in [g['name'] for g in not_decision_fields]:
                    msg = f'Found duplicate field name {property}. Fields in a policy must have unique names.'
                    raise InvalidPolicyStructure(message=msg)
                not_decision_fields.append(f)
            if not property in kwargs.keys():
                raise MissingPolicyField(message=f'Policy requires the {property} parameter. Found: {kwargs.keys()}')
            if not type(kwargs[property]) == prop_type:
                raise InvalidPolicyFieldType(
                    message=f'field {property} must be of type {prop_type}; got {type(kwargs[property])}.')
            # check that at the least, each field that is not a Decision field has a function on it that
            # can return the z3 boolref
            if not prop_type == Decision:
                if not hasattr(kwargs[property], 'get_cvc_boolterm'):
                    raise InvalidPolicyFieldType(
                        message=f'field {property} must have a function get_z3_boolref but it does not.')
            # this creates an attribute on the Policy object whose name is the name of the field and whose
            # value is the value of the kwarg of the same name.
            setattr(self, property, kwargs[property])
        # todo -- decide about this
        # if we did not find a decision, we can either raise an error or add one automatically. for now, we will raise an error
        if not found_decision:
            raise InvalidPolicyStructure(
                message='A policy class is required to have exactly one Deciion field; and did not find one.')
        self.all_fields = fields
        self.fields = not_decision_fields
        self.field_names = [f['name'] for f in self.fields]


class PolicyEquivalenceChecker(object):
    """
    Class for reasoning formally about two sets of policies.
    """

    def __init__(self, policy_type: type, policy_set_p: list[BasePolicy], policy_set_q: list[BasePolicy], slv:cvc5.Solver):
        self.slv = slv

        self.string = self.slv.getStringSort()

        # the type of policies this policy checker is working with. Should be a child of BasePolicy
        self.policy_type = policy_type

        # the two sets of policies
        self.policy_set_p = policy_set_p
        self.policy_set_q = policy_set_q

        # one free string variable for each dimensions of a policy
        #print("\n Initializing self.free_variables -----\n")
        self.free_variables = []
        #self.free_variables_type = {}
        # the list of proerty names that will be contributing to the z3 boolean expression constraints.
        # the Decision field is treated in a special way and does not contribute a z3 boolean expression so we skip it
        # here.
        self.z3_constraint_property_names = [f['name'] for f in self.policy_type.fields if not f['type'] == Decision]
        #print("\n contraint names: ", self.z3_constraint_property_names)
        # statements related to the policy sets (1 for each)
        self.P, self.Q = self.get_statements()


    def get_allow_policies(self, policy_set: list[BasePolicy]):
        return [p for p in policy_set if getattr(p, p.decision_field).decision == 'allow']

    def get_deny_policies(self, policy_set: list[BasePolicy]):
        return [p for p in policy_set if getattr(p, p.decision_field).decision == 'deny']

    def get_match_list(self, policy_set: list[BasePolicy]):
        and_list = []
        for p in policy_set:

            #boolrefs = [getattr(p, f).get_z3_boolref(f) for f in self.z3_constraint_property_names]
            #boolterms  = [getattr(p, f).get_cvc_boolterm(f) for f in self.z3_constraint_property_names]
            boolterms = []
            for f in self.z3_constraint_property_names:
                # String variables
                free_var = None
                #print("\n self.free_variables : ", self.free_variables)
                if len(self.free_variables) == 0 :
                    free_var = self.slv.mkConst(self.string, f)
                    #print(" Appending ", free_var, " to self.free_variables ", self.free_variables)
                    self.free_variables.append(free_var)


                #print("\n ---  len of self.free_variables: ", len(self.free_variables))
                flag = False
                for v in self.free_variables:
                    #print("\n v = ", v, "  type= ", type(v), " getSymbol: ", v.getSymbol())
                    #print("  f : ", f)
                    if f == v.getSymbol() :
                        free_var = v
                        flag = True
                        break
                if flag == False:
                    free_var = self.slv.mkConst(self.string, f)
                    #print("\n Appending ", free_var, " to self.free_variables ", self.free_variables)
                    self.free_variables.append(free_var)

                term = getattr(p, f).get_cvc_boolterm(free_var)
                boolterms.append(term)




            #and_list.append(z3.And(*boolrefs))
            if len(boolterms) == 1:
                and_list.append(boolterms[0])
            else:
                and_list.append(self.slv.mkTerm(Kind.AND,*boolterms))

        #print("\n free_variables : = ", self.free_variables)
        #print(and_list)
        return and_list

    def get_policy_set_re(self, allow_match_list: list, deny_match_list: list):
        if len(allow_match_list) == 1:
            allow_or_term = allow_match_list[0]
        else:
            allow_or_term = self.slv.mkTerm(Kind.OR, *allow_match_list)
        if len(deny_match_list) == 0:
           return allow_or_term
        else:

            if len(deny_match_list) == 1:
                return self.slv.mkTerm(Kind.AND,
                    allow_or_term,
                    self.slv.mkTerm(Kind.NOT, deny_match_list[0]))
            else:
                return self.slv.mkTerm(Kind.AND,
                                       self.slv.mkTerm(Kind.OR, allow_or_term),
                                           self.slv.mkTerm(Kind.NOT,
                                                      self.slv.mkTerm(Kind.AND,*deny_match_list)))

    def get_statements(self):
        for p_set in [self.policy_set_p, self.policy_set_q]:
            #print("\n p_set = ", p_set)
            allow_match_list = self.get_match_list(self.get_allow_policies(p_set))
            #print("\n len(allow match list) = ", len(allow_match_list))
            deny_match_list = self.get_match_list(self.get_deny_policies(p_set))
            #print("\n len(deny_match_list) = ", len(deny_match_list))
            yield self.get_policy_set_re(allow_match_list, deny_match_list)
        #print("\n len(allow match list) = ", len(allow_match_list))
        #print("\n len(deny_match_list) = ", len(deny_match_list))

    def prove(self, statement_1, statement_2):
        stmt = self.slv.mkTerm(Kind.NOT,self.slv.mkTerm(Kind.IMPLIES, statement_1, statement_2))
        result = self.slv.checkSatAssuming(stmt)
        #print("--- Result:----  ", result)
        if result.isUnsat():
            print (" Result is unsat. Hence, PROVED \n")
            #unsatCore = self.slv.getUnsatCore();
            #print("\n unsat core size: ", len(unsatCore))
            #print("\n unsat core: ", unsatCore)

        elif result.isSat():
            print(" Result is sat. ")
            print(" counterexample")
            for fvar in self.free_variables:
                print("\n", fvar.getSymbol(), "= ", self.slv.getValue(fvar))

        else:
            print(" ------ Unknown  ----- ")


        return result

    def p_implies_q(self):
        print("\n Prove p => q ")
        result = self.prove(self.P, self.Q)
        print("\n Summary: p => q result: ", result )
        return result

    def q_implies_p(self):
        print("\n Prove q => p : ")
        result = self.prove(self.Q, self.P)
        print("\n Summary: q => p: ", result)
        return result
