from contextlib import contextmanager
from ._config import Config


DEFAULT_CONFIG: Config = Config()


@contextmanager
def saved_state():
    global DEFAULT_CONFIG
    saved = DEFAULT_CONFIG
    try:
        yield
    finally:
        DEFAULT_CONFIG = saved
