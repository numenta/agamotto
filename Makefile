docs:
	pandoc --from=markdown --to=rst --output=README.rst README.md

upload: docs
	python setup.py sdist upload -r pypi
	python setup.py bdist_wheel upload -r pypi

