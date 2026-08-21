import time
from contextlib import contextmanager

                                                           
TIMINGS = {}


def _record(module, component, seconds):
    TIMINGS.setdefault(module, {})[component] = seconds


@contextmanager
def timed(module, component="__module__"):
    start = time.perf_counter()
    try:
        yield
    finally:
        _record(module, component, time.perf_counter() - start)


def module_total(module):
    comps = TIMINGS.get(module, {})
    subs = {k: v for k, v in comps.items() if k != "__module__"}
    if subs:
        return sum(subs.values())
    return comps.get("__module__", 0.0)


def reset():
    TIMINGS.clear()
