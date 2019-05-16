from setuptools import setup, find_packages

setup(
    name="capfuzz",
    version="0.0.1",
    description="Yet another https proxy to capture and fuzz web apis. Tailor made for fuzzing Mobile App APIs & web services with a scriptable interface. CapFuzz is built on top of [mitmproxy](https://mitmproxy.org/)",
    author="Ajin Abraham",
    author_email="ajin25@gmail.com",
    license='GPL v3',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3'
    ],
    packages=find_packages(include=[
        "capfuzz", "capfuzz.*", "capfuzz.core", "capfuzz.fuzzer", "capfuzz.web",
    ]),
    entry_points={
        'console_scripts': [
            "capfuzz = capfuzz.__main__:main",
        ]
    },
    include_package_data=True,
    url="http://pypi.python.org/pypi/capfuzz/",
    long_description="Yet another https proxy to capture and fuzz web apis. Tailor made for fuzzing Mobile App APIs & web services with a scriptable interface. CapFuzz is built on top of[mitmproxy](https: // mitmproxy.org/)",
    install_requires=[
        "mitmproxy==3.0.2",
    ],
)
