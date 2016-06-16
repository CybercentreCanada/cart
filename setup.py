"""CaRT PiP Installer"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
from cart import cart

setup(
    name='cart',
    version='%s.%s.%s' % (cart.__build_major__, 
                          cart.__build_minor__, 
                          cart.__build_micro__),
    description='CaRT Neutering format',
    long_description="Compressed and RC4 Transport (CaRT) Neutering format.",
    url='https://github.com/CommunicationsSecurityEstablishment/cart',
    author='sgaron',
    author_email='sgaron.cse@gmail.com',
    license='MIT',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
    keywords='cart',
    packages=find_packages(exclude=['docs', 'unittest']),
    install_requires=['pycrypto'],
    extras_require={},
    package_data={},
    data_files=[],
    entry_points={
        'console_scripts': [
            'cart=cart:main',
        ],
    },
)
