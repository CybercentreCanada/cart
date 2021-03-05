"""CaRT PiP Installer"""

from setuptools import setup, find_packages

import os.path
here = os.path.abspath(os.path.dirname(__file__))
major, minor, micro = 0, 0, 0
exec(open(os.path.join(here, 'cart/version.py')).read())


setup(
    name='cart',
    version='%s.%s.%s' % (major, minor, micro),
    description='CaRT Neutering format',
    long_description="Compressed and RC4 Transport (CaRT) Neutering format. This is a file format that is used to "
                     "neuter malware files for distribution in the malware analyst community.",
    url='https://bitbucket.org/cse-assemblyline/cart',
    author='CSE-CST Assemblyline development team',
    author_email='assemblyline@cyber.gc.ca',
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    keywords='neutering format malware cart stix development gc canada cse-cst cse cst cccs cyber',
    packages=find_packages(exclude=['docs', 'pipelines', 'unittests']),
    install_requires=['pycryptodome'],
    entry_points={
        'console_scripts': [
            'cart=cart:main',
        ],
    },
    python_requires=">=3.6",
)
