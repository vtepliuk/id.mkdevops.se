# -*- coding: utf-8 -*-
"""Create an application instance."""

from __future__ import absolute_import, division, print_function, unicode_literals

from flask.helpers import get_debug_flag

from xl_auth.app import create_app
from xl_auth.settings import DevConfig, ProdConfig

CONFIG = DevConfig if get_debug_flag() else ProdConfig

app = create_app(CONFIG)
