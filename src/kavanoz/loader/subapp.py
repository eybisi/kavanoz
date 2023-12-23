from androguard.core.apk import APK
from androguard.core.dex import DEX
from kavanoz.unpack_plugin import Unpacker
from kavanoz.utils import xor


class LoaderSubapp(Unpacker):
    def __init__(self, apk_obj: APK, dvms, output_dir):
        super().__init__(
            "loader.subapp",
            "Unpacker for chinese packer1, Beingyi",
            apk_obj,
            dvms,
            output_dir,
        )

    def start_decrypt(self, native_lib: str = ""):
        self.logger.info("Starting to decrypt")
        package_name = self.apk_object.get_package()
        self.decrypted_payload_path = None
        if package_name != None:
            self.brute_assets(package_name)

    def brute_assets(self, key: str):
        self.logger.info("Starting brute-force")
        asset_list = self.apk_object.get_files()
        for filepath in asset_list:
            f = self.apk_object.get_file(filepath)
            if self.solve_encryption(f, key):
                self.logger.info("Decryption finished! unpacked.dex")
                return self.decrypted_payload_path
        return None

    def solve_encryption(self, file_data, key):
        if len(key) < 3 or len(file_data) < 3:
            return False
        xored_h = file_data[0] ^ key[0].encode("utf-8")[0]
        xored_h2 = file_data[1] ^ key[1].encode("utf-8")[0]
        xored_h3 = file_data[2] ^ key[2].encode("utf-8")[0]
        if xored_h != ord("d") or xored_h2 != ord("e") or xored_h3 != ord("x"):
            return False
        xored_data = xor(file_data, key.encode("utf-8"))
        if self.check_and_write_file(xored_data):
            return True
        return False
