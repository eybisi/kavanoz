from androguard.core.apk import APK
from kavanoz.unpack_plugin import Unpacker
from kavanoz.utils import xor


class LoaderMoqhao(Unpacker):
    """
    Read asset files. Try to decrypt with : file[11] is xor key to decrypt file[12:]
    """

    def __init__(self, apk_obj: APK, dvms, output_dir):
        super().__init__(
            "loader.moqhao", "Unpacker for moqhao", apk_obj, dvms, output_dir
        )

    def start_decrypt(self, native_lib: str = ""):
        self.logger.info("Starting to decrypt")
        self.decrypted_payload_path = None
        self.brute_assets()

    def brute_assets(self):
        self.logger.info("Starting brute-force")
        asset_list = self.apk_object.get_files()
        for filepath in asset_list:
            if "assets/" in filepath:
                f = self.apk_object.get_file(filepath)
                if self.solve_encryption(f):
                    self.logger.info(
                        f"Decryption finished! {self.decrypted_payload_path}"
                    )

    def lazy_check(self, apk_obj, dvms) -> bool:
        file_list = apk_obj.get_files()
        one_asset = any("assets/" in x for x in file_list)
        native_lib = any("lib/" in x for x in file_list)
        return one_asset and native_lib

    def solve_encryption(self, file_data):
        if len(file_data) < 12:
            return
        first_12 = file_data[:12]
        xor_key = first_12[11].to_bytes(1, "little")
        xord_data = xor(file_data[12:], xor_key)
        if self.check_and_write_file(xord_data):
            return True
        else:
            return False
        return False
