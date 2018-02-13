#!/usr/bin/python
import sys, os
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/ManualScanner/")
from app import create_app
application = create_app()
application.secret_key = 'p9Bv<3Eid9%$i01'
