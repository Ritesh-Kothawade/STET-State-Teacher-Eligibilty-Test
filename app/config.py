import os


class Config(object):
    SECRET_KEY = 'mysecretkey'
    FLASK_APP = 'STET.py'
    FLASK_ENV = os.environ.get('FLASK_ENV')
    FLASK_DEBUG = True

