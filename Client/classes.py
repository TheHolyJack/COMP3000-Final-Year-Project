import json
from config import config as personal_conf
import os
import datetime
from flask_sqlalchemy import SQLAlchemy

"""
Classes file.

Not many classes have been needed to be used.

"""

class APConfig:
    SCHEDULER_API_ENABLED = True


global LogFile
current_time = datetime.datetime.now()

class Logger():
    """Logging Class"""
    log_type = "Default"
    def __init__(self, log_type):
        """
        Used to log events.
        :param log_type: Log type to be used.
        """
        self.log_type = log_type

    def __repr__(self):
        return f"<Logger|{self.log_type}"

    def Log(self, *args):
        """

        :param args: Arguments to log.
        :return: None
        """
        if personal_conf['debug']:
            print(f"<Logger | {self.log_type}> {args}.")



