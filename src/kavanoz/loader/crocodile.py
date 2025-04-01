from Crypto.Cipher import AES

from androguard.core.apk import APK
from kavanoz.unpack_plugin import Unpacker
from kavanoz.utils import unpad_pkcs5


class LoaderCrocodile(Unpacker):
    """
    Read asset files. Try to decrypt with AES; key [32:48] iv [48:64], size [64:72], data [72:]
    """

    def __init__(self, apk_obj: APK, dvms, output_dir):
        super().__init__(
            "loader.crocodile", "Unpacker for crocodile", apk_obj, dvms, output_dir
        )

    def start_decrypt(self, native_lib: str = ""):
        self.logger.info("Starting to decrypt for crocodile")
        self.decrypted_payload_path = None
        self.brute_assets()

    def brute_assets(self):
        asset_list = self.apk_object.get_files()
        for filepath in asset_list:
            if "assets/" in filepath:
                f = self.apk_object.get_file(filepath)
                if self.solve_encryption(f):
                    self.logger.info(
                        f"Decryption finished! {self.decrypted_payload_path}, found it in {filepath}"
                    )

    def solve_encryption(self, file_data):
        if len(file_data) < 72:
            return
        aes_key = file_data[32:48]
        aes_iv = file_data[48:64]
        aes_size = file_data[64:72]
        aes_data = file_data[72:]
        if len(aes_data) % 16 != 0:
            return
        aes_size = int.from_bytes(aes_size, "big")
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        dec_data = cipher.decrypt(aes_data)
        try:
            dec_data = unpad_pkcs5(dec_data)
        except ValueError:
            # self.logger.error("Unpadding failed")
            return
        if len(dec_data) != aes_size:
            return
        if self.check_and_write_file(dec_data):
            return True
        else:
            return False
