from dataclasses import dataclass
from typing import Any, Optional, Type, Union


@dataclass
class Steganography:
    name: str
    label: str
    param_type: Type[Union[int, float, bool, str]]
    default: Any = None
    options: Optional[list[Any]] = None
    min: Optional[float] = None
    max: Optional[float] = None


@dataclass
class Cryptography:
    name: str
    label: str
    param_type: Type[Union[int, float, bool, str, bytes]] = str
    default: Any = None
    options: Optional[list[Any]] = None
    min: Optional[float] = None
    max: Optional[float] = None
