import os, tempfile, tarfile  # noqa: E401
from hashlib import md5
from modules.extraction import Extractor


class Firmware:
    def __init__(self, firmware_file_path):
        self.firmware_file_path = firmware_file_path
        self.file_name = os.path.basename(firmware_file_path)
        self.firmware_data = self.read_firmware()
        self.extracted_filesystem = self.extract_filesystem()
        if not self.extract_filesystem:
            self.filesystem_path = self.unzip_filesystem()
        else:
            self.filesystem_path = None


    def read_firmware(self):
        try:
            with open(self.firmware_file_path, "rb") as file:
                firmware_data = file.read()
            return firmware_data
        except FileNotFoundError:
            print(f"File not found: {self.firmware_file_path}")
            return None

    def is_encrypted(self):
        return False

    def get_entropy(self):
        #chunk_wise_entropy(self.firmware_data)

        return False

    def extract_filesystem(self):
        extract = Extractor(
            self.firmware_file_path, "images/filesystem", True, False, True, None, None
        )
        extract.extract()
        filesystem_name = (
            self.file_name + "_" + md5(self.firmware_data).hexdigest() + ".tar.gz"
        )
        filesystem_path = os.path.join(extract.output_dir, filesystem_name)
        if os.path.isfile(filesystem_path):
            return filesystem_path

        return None

    def extract_kernel(self):
        extract = Extractor(
            self.firmware_file_path, "images/kernel", False, True, True, None, None
        )
        extract.extract()

    def unzip_filesystem(self):
        if self.extracted_filesystem:
            temp_folder = tempfile.mkdtemp()
            # Extract the tar.gz file into the temporary folder
            try:
                with tarfile.open(self.extracted_filesystem, "r:gz") as tar:
                    tar.extractall(path=temp_folder)
                return temp_folder
            except tarfile.TarError as e:
                print(f"Error extracting tarfile: {e}")
        else:
            print("Filesystem not found!!!")
        return 

    def get_firmware_size(self):
        if self.firmware_data:
            return len(self.firmware_data)
        else:
            return None

    def static_analysis(self):
        # version = VersionDetection(self)
        return

    def display_firmware_info(self):
        size = self.get_firmware_size()
        if size is not None:
            print(f"Firmware file: {self.firmware_file_path}")
            print(f"Firmware size: {size} bytes")
            if self.is_encrypted():
                print("Firmware is encrypted.")
            else:
                print("Firmware is not encrypted.")
