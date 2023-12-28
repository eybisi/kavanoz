from androguard.core.apk import APK
from androguard.core.dex import DEX
from kavanoz.unpack_plugin import Unpacker
import struct


class LoaderMultidexHeader(Unpacker):
    def __init__(self, apk_obj: APK, dvms, output_dir):
        super().__init__(
            "loader.multidex.header", "Unpacker for multidex", apk_obj, dvms, output_dir
        )

    def start_decrypt(self, native_lib: str = ""):
        self.logger.info("Starting to decrypt")
        self.decrypted_payload_path = None
        self.brute_assets()

    def brute_assets(self):
        self.logger.info("Starting brute-force")
        asset_list = self.apk_object.get_files()
        for filepath in asset_list:
            f = self.apk_object.get_file(filepath)
            if self.read_size_append_dex(f):
                self.logger.info("Decryption finished! unpacked.dex")
                return self.decrypted_payload_path
        return None

    def read_size_append_dex(self, file_data):
        # dex_header_size_off = 0x20
        if len(file_data) <= 0x20 - 3 + 4:
            return
        size = struct.unpack("<I", file_data[0x20 - 3 : 0x20 - 3 + 4])[0]
        if len(file_data) + 3 != size:
            return
        file_data = b"dex" + file_data
        if self.check_and_write_file(file_data):
            return True
        return False
