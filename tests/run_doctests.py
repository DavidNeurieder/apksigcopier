#!/usr/bin/env python3
# encoding: utf-8

"""Run doctests across all apksigcopier modules using proper package imports."""

import doctest
import importlib
import pkgutil
import sys

import apksigcopier


def main():
    failures = 0
    total = 0
    for importer, name, ispkg in pkgutil.walk_packages(
            apksigcopier.__path__, "apksigcopier."):
        if ispkg:
            continue
        mod = importlib.import_module(name)
        results = doctest.testmod(mod)
        total += 1
        if results.failed:
            print(f"FAIL  {name}: {results.failed} failure(s)")
            failures += results.failed
        else:
            print(f"PASS  {name}")
    print(f"\n{total - failures}/{total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
