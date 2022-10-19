
from typing import Optional


class BaseCloudz3SecError(Exception):
    def __init__(self, message: Optional[str]) -> None:
        self.message = message
        print(message)


class InvalidCharacterError(BaseCloudz3SecError):
    """
    Raised when a character set of field name includes a reserved character.
    """
    pass


class InvalidValueError(BaseCloudz3SecError):
    """
    Raised when a value passed to an Re type is not allowed.
    """
    pass


class InvalidStringTupleStructure(BaseCloudz3SecError):
    """
    Raised when a StringTupleRe contstructor is passed an improperly formatted fields argument. 
    """
    pass


class MissingInstanceData(BaseCloudz3SecError):
    """
    Base class that is raised when a type does not have required data set. Used in base class methods; in child classes,
    one of the more specific exceptions can be thrown.
    """
    pass


class MissingStringEnumData(BaseCloudz3SecError):
    """
    Raised when a StringEnum type does not have required data set.
    """
    pass


class MissingStringReData(BaseCloudz3SecError):
    """
    Raised when a StringRe type does not have required data set.
    """
    pass


class MissingStringTupleData(BaseCloudz3SecError):
    """
    Raised when a StringTuple type does not have required data set.
    """
    pass

class InvalidStringTupleData(BaseCloudz3SecError):
    """
    Raised when a StringTupleRe set_data method is passed an improperly formatted key-word argument. 
    """
    pass


class InvalidPolicyStructure(BaseCloudz3SecError):
    """
    Raised when a Policy contstructor is passed an improperly formatted fields argument. 
    """
    pass


class MissingPolicyField(BaseCloudz3SecError):
    """
    Raised when a Policy contstructor is not passed an instance of one its speficied fields. 
    """
    pass


class InvalidPolicyFieldType(BaseCloudz3SecError):
    """
    Raised when a Policy contstructor is passed a field with the wrong type. 
    """
    pass