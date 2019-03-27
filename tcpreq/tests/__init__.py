from typing import Type, Tuple

from .base import BaseTest

# List of tests to perform if no explicit list of tests is given
DEFAULT_TESTS: Tuple[Type[BaseTest], ...] = ()
