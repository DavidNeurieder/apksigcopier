from contextlib import contextmanager


exclude_all_meta = False
copy_extra_bytes = False
skip_realignment = False


@contextmanager
def saved_state():
    """Save and restore global state (exclude_all_meta, copy_extra_bytes,
    skip_realignment)."""
    global exclude_all_meta, copy_extra_bytes, skip_realignment
    saved = exclude_all_meta, copy_extra_bytes, skip_realignment
    try:
        yield
    finally:
        exclude_all_meta, copy_extra_bytes, skip_realignment = saved
