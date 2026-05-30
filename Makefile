SHELL     := /bin/bash
PYTHON    ?= python3
PYTHONPATH ?= src

PYCOV     := PYTHONPATH=src $(PYTHON) -mcoverage run --source=src/apksigcopier
PYCOVCLI  := PYTHONPATH=src $(PYCOV) -a -mapksigcopier._cli

export PYTHONWARNINGS := default

.PHONY: all install test test-cli doctest coverage lint lint-extra clean cleanup
.PHONY: test-apks test-apks-compare-in test-apks-compare-self test-apks-copy test-apksigner35

all: apksigcopier.1

install:
	$(PYTHON) -mpip install -e .

test: test-cli doctest lint lint-extra

test-cli:
	# TODO
	PYTHONPATH=src $(PYTHON) -mapksigcopier --version

doctest:
	# NB: uses tests/apks/apks/*.apk
	PYTHONPATH=src $(PYTHON) tests/run_doctests.py

coverage:
	# NB: uses tests/apks/apks/*.apk & modifies .tmp
	mkdir -p .tmp/meta
	PYTHONPATH=src $(PYCOV) tests/run_doctests.py
	PYTHONPATH=src $(PYCOVCLI) extract tests/apks/apks/golden-aligned-v1v2v3-out.apk .tmp/meta
	PYTHONPATH=src $(PYCOVCLI) patch .tmp/meta tests/apks/apks/golden-aligned-in.apk .tmp/patched.apk
	PYTHONPATH=src $(PYCOVCLI) copy tests/apks/apks/golden-aligned-v1v2v3-out.apk \
	                 tests/apks/apks/golden-aligned-in.apk .tmp/copied.apk
	PYTHONPATH=src $(PYCOVCLI) compare tests/apks/apks/golden-aligned-v1v2v3-out.apk \
	         --unsigned tests/apks/apks/golden-aligned-in.apk
	apksigner verify --verbose .tmp/patched.apk
	apksigner verify --verbose .tmp/copied.apk
	$(PYTHON) -mcoverage html
	$(PYTHON) -mcoverage report

test-apks: test-apks-compare-in test-apks-compare-self test-apks-copy test-apksigner35

test-apks-compare-in:
	cd tests && PYTHONPATH=../src ./test-compare-in.py

test-apks-compare-self:
	cd tests && diff -Naur test-compare-self.out <( PYTHONPATH=../src ./test-compare-self.py \
	  2>&1 \
	  | sed -r 's!/tmp/[^/]*/!/tmp/.../!' \
	  | sed -r 's!Expected: <[0-9a-f]+>, actual: <[0-9a-f]+>!Expected: <...>, actual: <...>!' )

test-apks-copy:
	cd tests && diff -Naur test-copy.out <( PYTHONPATH=../src $(PYTHON) ./test-copy.py )

test-apksigner35:
	cd tests && PYTHONPATH=../src $(PYTHON) ./test-apksigner35.py

lint:
	flake8 src/apksigcopier/*.py
	pylint src/apksigcopier/*.py

lint-extra:
	mypy --strict --disallow-any-unimported src/apksigcopier/*.py

clean: cleanup
	rm -fr *.egg-info/
	rm -fr src/*.egg-info/

cleanup:
	find -name '*~' -delete -print
	rm -fr __pycache__/ .mypy_cache/
	rm -fr build/ dist/
	rm -fr .coverage htmlcov/
	rm -fr apksigcopier.1
	rm -fr .tmp/

%.1: %.1.md
	pandoc -s -t man -o $@ $<
	sed -ri 's!-!\\-!g' $@

.PHONY: _package _publish

_package:
	SOURCE_DATE_EPOCH="$$( git log -1 --pretty=%ct )" \
	  $(PYTHON) -mbuild
	twine check dist/*

_publish: cleanup _package
	read -r -p "Are you sure? "; \
	[[ "$$REPLY" == [Yy]* ]] && twine upload dist/*
