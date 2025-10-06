import argparse
from modules.firmware import Firmware

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyse Firmwares")
    parser.add_argument("-f", "--file", type=str, help="Path to the Firmware file")
    parser.add_argument(
        "-k", action="store_true", help="Extract Kernel from the Firmware"
    )
    args = parser.parse_args()
    # print(args)
    if args.file:
        firmware_file_path = args.file
        firmware = Firmware(firmware_file_path)
        if args.k:
            firmware.extract_kernel()
    else:
        parser.print_help()
