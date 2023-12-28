from androguard.core.apk import APK
from androguard.core.dex import DEX
from kavanoz.unpack_plugin import Unpacker
from kavanoz.utils import xor


class LoaderSimple(Unpacker):
    def __init__(self, apk_obj: APK, dvms, output_dir):
        super().__init__(
            "loader.simple", "Simple methods to unpack", apk_obj, dvms, output_dir
        )

    def start_decrypt(self, native_lib: str = ""):
        self.logger.info("Starting to decrypt")
        package_name = self.apk_object.get_package()
        self.decrypted_payload_path = None
        if package_name != None:
            if self.brute_assets(package_name):
                return

    def brute_assets(self, key: str):
        self.logger.info("Starting brute-force")
        asset_list = self.apk_object.get_files()
        for filepath in asset_list:
            f = self.apk_object.get_file(filepath)
            if self.try_one_byte_xor(f):
                return self.decrypted_payload_path
        return None

    def try_one_byte_xor(self, file_data):
        for k in range(1, 256):
            xored_data = xor(file_data[:16], k.to_bytes(1, "little"))
            if not self.check_header(xored_data):
                continue
            self.logger.info(f"Found single byte xor key : {k}")
            xored_data = xor(file_data, k.to_bytes(1, "little"))
            if self.check_and_write_file(xored_data):
                return True
        return False
