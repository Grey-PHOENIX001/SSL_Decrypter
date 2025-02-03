import logging
import os
import psutil
import shutil
from subprocess import Popen, PIPE
from typing import List

# Setting up logging with console output
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)

logging.getLogger('').addHandler(console_handler)
logging.basicConfig(
    level=logging.INFO,
    handlers=[console_handler],
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def list_network_interfaces() -> List[str]:

    interfaces = []
    try:
        if os.name == 'nt':  # Windows
            # Use psutil to list network interfaces on Windows
            interfaces = [interface for interface, addrs in psutil.net_if_addrs().items() if 'Ethernet' in interface or 'Wi-Fi' in interface]
        elif os.name == 'posix':  # Linux/macOS
            # List all interfaces in /sys/class/net for Linux
            net_files = os.listdir('/sys/class/net/')
            for interface in net_files:
                if 'eth' in interface or 'wlan' in interface:
                    interfaces.append(interface)
        else:
            logger.error("Unsupported OS. Only Linux and Windows are supported for network interface listing.")
            return []

    except Exception as e:
        logger.error(f"Error listing network interfaces: {e}")
        return []

    # Filter and deduplicate interface names
    unique_interfaces = list(set(interfaces))
    if not unique_interfaces:
        logger.warning("No network interfaces found. Capture will be disabled.")
        return []
    else:
        return sorted(unique_interfaces)

def capture_ssl_tls_traffic(selected_interface: str, tshark_path: str, output_file: str) -> None:
  
    try:
        # Verify tshark installation
        if not os.path.isfile(tshark_path):
            logger.error("tshark path is invalid. Please provide a valid path.")
            raise FileNotFoundError("Invalid tshark path")

        # Capture packets
        command = [
            tshark_path,
            '-i', selected_interface,
            '-f', 'tcp',
            '-w', output_file
        ]

        logger.info(f"Starting capture on interface {selected_interface}...")

        with Popen(command, stdout=PIPE, stderr=PIPE) as proc:
            stdout, stderr = proc.communicate()

            if proc.returncode != 0:
                error_message = stderr.decode()
                logger.error(f"Capture failed. Error: {error_message}")
                raise Exception(f"Packet capture failed with error: {error_message}")

        logger.info(f"Successfully captured SSL/TLS traffic and saved to {output_file}")
    except Exception as e:
        logger.error(f"Error during packet capture: {e}")
        raise

def main() -> None:

    try:
        logger.info("Starting SSL Traffic Capture")

        # Get list of available interfaces
        interfaces = list_network_interfaces()

        if not interfaces:
            logger.warning("No suitable network interfaces found. Capture will be disabled.")
            return

        print("\nAvailable Network Interfaces:")
        for index, interface in enumerate(interfaces, 1):
            print(f"{index}. {interface}")

        # Get user's choice
        while True:
            try:
                choice = input("\nEnter the number of the interface you want to use (or press Enter for default): ")

                if not choice and interfaces:
                    selected_interface = interfaces[0]
                elif choice.isdigit() and 1 <= int(choice) <= len(interfaces):
                    selected_interface = interfaces[int(choice) - 1]
                else:
                    logger.error("Invalid choice. Please select a valid interface number or press Enter for default.")
                    continue

                break
            except Exception as e:
                logger.error(f"Error processing input: {e}")

        # Ask user to provide the tshark path
        while True:
            try:
                tshark_path = ('your_tshark_path_here')
                if not tshark_path:
                    tshark_path = shutil.which('tshark')
                break
            except Exception as e:
                logger.error(f"Error processing input: {e}")

        # Set output file path with user's home directory expanded (~)
        output_file = os.path.expanduser('./tmp.pcap')
        capture_ssl_tls_traffic(selected_interface, tshark_path, output_file)
    except Exception as e:
        logger.error(f"An error occurred during execution: {str(e)}")
    finally:
        logger.info("Packet capture process completed. Exiting.")

if __name__ == "__main__":
    main()
