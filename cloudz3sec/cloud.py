from cloudz3sec import core
from cloudz3sec.errors import MissingStringEnumData, InvalidValueError

ALPHANUM_SET = set('abcdefghijklmnopqrstuvwxyz0123456789')

PATH_CHAR_SET = set('abcdefghijklmnopqrstuvwxyz0123456789_/')


class HTTPVerbRe(core.StringEnumRe):
    """
    Class representing HTTP verbs.
    """
    def __init__(self) -> None:
        values = ['GET', 'POST', 'PUT', 'DELETE']
        super().__init__(values)


class Action(HTTPVerbRe):
    """
    Class representing an action on a resource; i.e., an HTTP verb.
    a = Action()
    a.set_data('GET')
    """
    def __init__(self) -> None:
        super().__init__()
        self.data = {}

    def set_data(self, verb):
        self.data['verb'] = verb
    
    def to_re(self):
        if not self.data:
            raise MissingStringEnumData(message=f'No data found on {type(self)} object; was set_data() called?')
        self.re = super().to_re(value=self.data['verb'])
        return self.re


class SiteRe(core.StringEnumRe):
    """
    Class representing the sites in a platform.

    `sites` - the list of sites defined in the platform.
    """
    def __init__(self, sites: list[str]):
        super().__init__(sites)


class TenantRe(core.StringEnumRe):
    """
    Class representing the set of tenants in a platform.
    `tenants` - the list of tenants defined in the platform.
    """
    def __init__(self, tenants: list[str]):
        super().__init__(tenants)


class ServiceRe(core.StringEnumRe):
    """
    Class representing the set of services in a platform.
    `services` - the list of allo
    """
    def __init__(self, services: list[str]):
        super().__init__(services)


class Principal(core.StringTupleRe):
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
    
    def __init__(self, sites: list[str], tenants: list[str]) -> None:
        self.sites = sites
        self.tenants = tenants
        fields = [
            {'name': 'site', 'type': SiteRe, 'kwargs': {'sites': sites} },
            {'name': 'tenant', 'type': TenantRe, 'kwargs': {'tenants': tenants}},
            {'name': 'username', 'type': core.StringRe, 'kwargs': {'charset': ALPHANUM_SET }}
        ]
        super().__init__(fields)


class Resource(core.StringTupleRe):
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
    
    def __init__(self, sites: list[str], tenants: list[str], services: list[str]) -> None:
        self.sites = sites
        self.tenants = tenants
        self.services = services
        fields = [
            {'name': 'site', 'type': SiteRe, 'kwargs': {'sites': sites} },
            {'name': 'tenant', 'type': TenantRe, 'kwargs': {'tenants': tenants} },
            {'name': 'service', 'type': ServiceRe, 'kwargs': {'services': services} },
            {'name': 'path', 'type': core.StringRe, 'kwargs': {'charset': PATH_CHAR_SET} },
        ]
        super().__init__(fields=fields)


class CloudPolicy(core.BasePolicy):
    """
    Class representing a security policy in a cloud system.
    """

    fields = [
        {'name': 'principal', 'type': Principal},
        {'name': 'resource', 'type': Resource},
        {'name': 'action', 'type': Action},
        {'name': 'decision', 'type': core.Decision}
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(fields=CloudPolicy.fields, **kwargs)


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
        return CloudPolicy(principal=p, resource=r, action=a, decision=core.Decision(decision))


