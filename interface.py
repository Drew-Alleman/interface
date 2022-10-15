if __name__ != '__main__':
    from core.utilities import *
else:
    from utilities import *

from subprocess import Popen
from time import sleep
import signal
import wifi
import os

class Interface:

    def __str__(self) -> str:
        return self.interface_name

    # def __eq__(self, intertfaceObject) -> bool:
    #     """ Checks to see if the inteface names are the same
    #     """
    #     try:
    #         return self.interface_name == intertfaceObject.interface_name
    #     except AttributeError:
    #         return False

    def __bool__(self) -> bool:
        """ Checks the operstate file to check the current status        
        """
        content = get_file_content(self.operstate)
        if not content or "up" not in content:
            return False
        return True

    def __init__(self, interface_name: str) -> None:
        """ Creates an Interface Manager

        Keyword Arguments
        interface_name -- Interface name to control
        """
        self.interface_name = interface_name
        self.mode = None
        self.tshark_session = False
        self.macchanger = True
        self.operstate = f"/sys/class/net/{self}/operstate"
        self.__are_tools_installed()
        if not os.path.exists(self.operstate):
            raise InvalidInterface(self)
