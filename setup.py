#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from setuptools import setup, find_packages

version = '0.1.1'

setup(name='pwdhash.py',
      version=version,
      description='Python Stanford PwdHash implementation',
      long_description="""\
Implementation of theft-resistant password generation algorithm known as
Stanford PwdHash (https://www.pwdhash.com/)""",
      classifiers=['Development Status :: 5 - Production/Stable',
                   'Environment :: Console',
                   'Environment :: X11 Applications',
                   'Environment :: MacOS X',
                   'License :: OSI Approved :: BSD License',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python',
                   'Topic :: Internet',
                   'Topic :: Software Development :: Libraries :: Python Modules',
                   'Topic :: Utilities'],
      keywords='pwdhash',
      author='Lev Shamardin',
      author_email='shamardin@gmail.com',
      url='https://github.com/abbot/pwdhash',
      license='BSD',
      py_modules=['pwdhash'],
      zip_safe=False,
      entry_points={ 'console_scripts': [ 'pwdhash = pwdhash:console_main' ] },
      )
      
