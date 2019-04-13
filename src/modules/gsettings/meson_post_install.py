#!/usr/bin/env python3

import os
import subprocess
import sys

datadir = sys.argv[1]

if not os.environ.get('DESTDIR'):
  schemadir = os.path.join(datadir, 'glib-2.0', 'schemas')
  print('Compiling gsettings schemas...')
  subprocess.call(['glib-compile-schemas', schemadir])

