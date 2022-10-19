
from typing import Optional


class BaseCloudCVCSecError(Exception):
    def __init__(self, message: Optional[str]) -> None:
        self.message = message
        print(message)


class InvalidCharacterError(BaseCloudCVCSecError):
    """
    Raised when a character set of field name includes a reserved character.
    """
    pass


class InvalidValueError(BaseCloudCVCSecError):
    """
    Raised when a value passed to an Re type is not allowed.
    """
    pass


class InvalidStringTupleStructure(BaseCloudCVCSecError):
    """
    Raised when a StringTupleRe contstructor is passed an improperly formatted fields argument. 
    """
    pass


class MissingInstanceData(BaseCloudCVCSecError):
    """
    Base class that is raised when a type does not have required data set. Used in base class methods; in child classes,
    one of the more specific exceptions can be thrown.
    """
    pass


class MissingStringEnumData(BaseCloudCVCSecError):
    """
    Raised when a StringEnum type does not have required data set.
    """
    pass


class MissingStringReData(BaseCloudCVCSecError):
    """
    Raised when a StringRe type does not have required data set.
    """
    pass


class MissingStringTupleData(BaseCloudCVCSecError):
    """
    Raised when a StringTuple type does not have required data set.
    """
    pass

class InvalidStringTupleData(BaseCloudCVCSecError):
    """
    Raised when a StringTupleRe set_data method is passed an improperly formatted key-word argument. 
    """
    pass


class InvalidPolicyStructure(BaseCloudCVCSecError):
    """
    Raised when a Policy contstructor is passed an improperly formatted fields argument. 
    """
    pass


class MissingPolicyField(BaseCloudCVCSecError):
    """
    Raised when a Policy contstructor is not passed an instance of one its speficied fields. 
    """
    pass


class InvalidPolicyFieldType(BaseCloudCVCSecError):
    """
    Raised when a Policy contstructor is passed a field with the wrong type. 
    """
    pass