"""
This module provides An example of using the core module classes to create a policy engine for a specific application domaing -- cloud
services. This example makes specific choices about what fields to include and their types. These choices won't be appropriate even for
all cloud services, but it serves as an example for making others.
"""
import cvc5
from cloudz3sec import cvc_core
from cloudz3sec.errors import MissingStringEnumData, InvalidValueError

ALPHANUM_SET = set('abcdefghijklmnopqrstuvwxyz0123456789')

PATH_CHAR_SET = set('abcdefghijklmnopqrstuvwxyz0123456789_/')






class SiteRe(cvc_core.StringEnumRe):
    """
    Class representing the sites in a platform.

    `sites` - the list of sites defined in the platform.
    """

    def __init__(self, sites: list[str], slv:cvc5.Solver):
        super().__init__(sites,slv)


class TenantRe(cvc_core.StringEnumRe):
    """
    Class representing the set of tenants in a platform.
    `tenants` - the list of tenants defined in the platform.
    """

    def __init__(self, tenants: list[str], slv:cvc5.Solver):
        super().__init__(tenants, slv)


class ServiceRe(cvc_core.StringEnumRe):
    """
    Class representing the set of services in a platform.
    `services` - the list of allo
    """

    def __init__(self, services: list[str], slv:cvc5.Solver):
        super().__init__(services, slv)


class Principal(cvc_core.StringTupleRe):
    """
    Class representing a "principal" in a cloud service; i.e., an identity in a cloud system.

    Examples:
    sites = ['tacc', 'uh']
    tenants = ['dev', 'cii', 'admmin', 'tacc']
    p = cloud.Prinicipal(sites=sites, tenants=tenants)
    p.set_data(site='tacc', tenant='dev', username='testuser*')
    simplify(InRe('tacc.dev.testuser12', p.to_re()))
    Out: True
    simplify(InRe('uh.dev.testuser12', p.to_re()))
    Out: False

    """

    def __init__(self, sites: list[str], tenants: list[str], slv: cvc5.Solver) -> None:
        self.sites = sites
        self.tenants = tenants
        fields = [
            {'name': 'site', 'type': SiteRe, 'kwargs': {'sites': sites, 'slv':slv}},
            {'name': 'tenant', 'type': TenantRe, 'kwargs': {'tenants': tenants, 'slv':slv}},
            {'name': 'username', 'type': cvc_core.StringRe, 'kwargs': {'charset': ALPHANUM_SET, 'slv':slv}},
        ]
        super().__init__(fields,slv)


class Resource(cvc_core.StringTupleRe):
    """
    Class representing a "resource" in a cloud service; i.e., a path on a service within a tenant at some site.

    Examples:
    sites = ['tacc', 'uh']
    tenants = ['dev', 'cii', 'admmin', 'tacc']
    services = ['actors', 'apps', 'files, 'jobs', 'systems']
    r = cloud.Resource(sites=sites, tenants=tenants, services=services)
    r.set_data(site='tacc', tenant='dev', service='apps', path='/app1')

    r.set_data(site='tacc', tenant='dev', service='files', path='/sys1/*')
    simplify(InRe('tacc.dev.files./sys1/some/path/on/sys1', r.to_re()))
      Out: True
    """

    def __init__(self, sites: list[str], tenants: list[str], services: list[str], slv: cvc5.Solver) -> None:
        self.sites = sites
        self.tenants = tenants
        self.services = services
        fields = [
            {'name': 'site', 'type': SiteRe, 'kwargs': {'sites': sites, 'slv':slv}},
            {'name': 'tenant', 'type': TenantRe, 'kwargs': {'tenants': tenants, 'slv':slv}},
            {'name': 'service', 'type': ServiceRe, 'kwargs': {'services': services, 'slv':slv}},
            {'name': 'path', 'type': cvc_core.StringRe, 'kwargs': {'charset': PATH_CHAR_SET, 'slv':slv}},
        ]
        super().__init__(fields=fields,slv=slv)


class Action(cvc_core.StringEnumRe):
    """
    Class representing an action on a resource; i.e., an HTTP verb.
    a = Action()
    a.set_data('GET')
    """

    def __init__(self, slv:cvc5.Solver):
        values = ['GET', 'POST', 'PUT', 'DELETE']
        super().__init__(values, slv)


class BasicCloudPolicy(cvc_core.BasePolicy):
    fields = [
        {'name': 'principal', 'type': Principal},
        {'name': 'resource', 'type': Resource},
        {'name': 'action', 'type': Action},
        {'name': 'decision', 'type': cvc_core.Decision}
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(fields=BasicCloudPolicy.fields, **kwargs)


class CloudPolicy(cvc_core.BasePolicy):
    """
    Class representing a security policy in a cloud system.
    """

    fields = [
        {'name': 'principal', 'type': Principal},
        {'name': 'resource', 'type': Resource},
        {'name': 'action', 'type': Action},
        #{'name': 'src_ip', 'type': cvc_core.IpAddr2},
        {'name': 'decision', 'type': cvc_core.Decision}
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(fields=CloudPolicy.fields, **kwargs)

class CloudExamplePolicy(cvc_core.BasePolicy):
    """
    Class representing a security policy in a cloud system.
    """

    fields = [
        {'name': 'principal', 'type': Principal},
        {'name': 'decision', 'type': cvc_core.Decision}
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(fields=CloudExamplePolicy.fields, **kwargs)


class BasicCloudPolicyManager(object):
    def __init__(self, sites=None, tenants=None, services=None):
        self.sites = sites
        if not self.sites:
            self.sites = ['tacc', 'uh']
        self.tenants = tenants
        if not self.tenants:
            self.tenants = ['admin', 'cii', 'dev', 'a2cps', 'tacc']
        self.services = services
        if not self.services:
            self.services = ['actors', 'apps', 'files', 'jobs', 'systems']

    def policy_from_strs(self, principal: str, resource: str, action: str, decision: str):
        p = Principal(sites=self.sites, tenants=self.tenants)
        parts = principal.split('.')
        if not len(parts) == 3:
            raise InvalidValueError(f'principal should be contain exactly 2 dot characters; got {principal}')
        p.set_data(site=parts[0], tenant=parts[1], username=parts[2])
        r = Resource(sites=self.sites, tenants=self.tenants, services=self.services)
        parts = resource.split('.')
        if not len(parts) == 4:
            raise InvalidValueError(f'resource should be contain exactly 3 dot characters; got {resource}')
        r.set_data(site=parts[0], tenant=parts[1], service=parts[2], path=parts[3])
        a = Action()
        a.set_data(action)
        return BasicCloudPolicy(principal=p, resource=r, action=a, decision=cvc_core.Decision(decision))


class CloudPolicyManager(object):
    """
    Convenience class for working with cloud policies.

    Examples:
    t =  cloud.CloudPolicyManager()
    p = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.files./sys1/*', 'GET', 'allow')
    """

    def __init__(self):
        self.sites = ['tacc', 'uh']
        self.tenants = ['admin', 'cii', 'dev', 'a2cps', 'tacc']
        self.services = ['actors', 'apps', 'files', 'jobs', 'systems']

    def policy_from_strs(self, principal: str, resource: str, action: str, src_ip: str, decision: str):
        p = Principal(sites=self.sites, tenants=self.tenants)
        parts = principal.split('.')
        if not len(parts) == 3:
            raise InvalidValueError(f'principal should be contain exactly 2 dot characters; got {principal}')
        p.set_data(site=parts[0], tenant=parts[1], username=parts[2])
        r = Resource(sites=self.sites, tenants=self.tenants, services=self.services)
        parts = resource.split('.')
        if not len(parts) == 4:
            raise InvalidValueError(f'resource should be contain exactly 3 dot characters; got {resource}')
        r.set_data(site=parts[0], tenant=parts[1], service=parts[2], path=parts[3])
        a = Action()
        a.set_data(action)

        try:
            ip_addr, netmasklen = src_ip.split('/')
        except ValueError:
            msg = "Could not get IP address and netmask length from src_ip ({src_ip}). " + \
                  f"Format should be A.B.C.D/E."
            raise InvalidValueError(msg)
        try:
            netmasklen = int(netmasklen)
        except:
            raise InvalidValueError(f"Got invalid netmask length from src_ip ({src_ip}). " + \
                                    "Format should be A.B.C.D/E where E is an integer.")

        ipaddr = cvc_core.IpAddr2(netmasklen)
        ipaddr.set_data(ip_addr=src_ip)
        return CloudPolicy(principal=p, resource=r, action=a, src_ip=ipaddr, decision=cvc_core.Decision(decision))

    def policy_from_strs1(self, principal: str, resource: str, action: str, decision: str, slv:cvc5.Solver):
        p = Principal(sites=self.sites, tenants=self.tenants, slv = slv)
        parts = principal.split('.')
        if not len(parts) == 3:
            raise InvalidValueError(f'principal should be contain exactly 2 dot characters; got {principal}')
        p.set_data(site=parts[0], tenant=parts[1], username=parts[2])
        r = Resource(sites=self.sites, tenants=self.tenants, services=self.services, slv = slv)
        parts = resource.split('.')
        if not len(parts) == 4:
            raise InvalidValueError(f'resource should be contain exactly 3 dot characters; got {resource}')
        r.set_data(site=parts[0], tenant=parts[1], service=parts[2], path=parts[3])
        a = Action(slv = slv)
        a.set_data(action)

        return CloudPolicy(principal=p, resource=r, action=a, decision=cvc_core.Decision(decision))



    def policy_from_strs(self, principal: str, decision: str, slv:cvc5.Solver):
        p = Principal(sites=self.sites, tenants=self.tenants, slv = slv)
        parts = principal.split('.')
        if not len(parts) == 3:
            raise InvalidValueError(f'principal should be contain exactly 2 dot characters; got {principal}')
        p.set_data(site=parts[0], tenant=parts[1], username=parts[2])
        return CloudExamplePolicy(principal=p, decision=cvc_core.Decision(decision))