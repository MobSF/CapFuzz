from setuptools import setup, find_packages

setup(
    # Application name:
    name="capfuzz",

    # Version number (initial):
    version="0.0.1",

    # Application author details:
    author="Ajin Abraham",
    author_email="ajin25@gmail.com",

    # Packages
    packages=find_packages(include=[
        "capfuzz", "capfuzz.*", "capfuzz.core", "capfuzz.fuzzer", "capfuzz.web",
    ]),
    entry_points={
        'console_scripts': [
            "capfuzz = capfuzz.__main__:main",
        ]
    },

    # Include additional files into the package
    include_package_data=True,

    # Details
    url="http://pypi.python.org/pypi/capfuzz/",

    #
    # license="LICENSE.txt",
    description="Capture Intercept and Fuzz",

    # long_description=open("README.txt").read(),

    # Dependent packages (distributions)
    install_requires=[
        "mitmproxy==3.0.2",
    ],
)