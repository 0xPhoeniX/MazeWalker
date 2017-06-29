# Name: config.py
# Description: The configuration options in a convenient format
#
import os


class Config():

    def __init__(self):
        """
        Basic configuration
        """

        # Paths, etc.
        self.root_dir = os.path.dirname(os.path.abspath(__file__))
        self.icons_path = self.root_dir + os.sep + 'images' + os.sep
