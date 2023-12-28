from androguard.core.apk import APK
from androguard.core.dex import DEX
from kavanoz.unpack_plugin import Unpacker
from kavanoz.utils import xor


class LoaderAppsealing(Unpacker):
    def __init__(self, apk_obj: APK, dvms, output_dir):
        super().__init__(
            "loader.appsealing", "Appsealing unpacker", apk_obj, dvms, output_dir
        )

    def lazy_check(self, apk_object, dvms):
        for f in self.apk_object.get_files():
            if "assets/AppSealing" in f:
                return True

    def start_decrypt(self, native_lib: str = ""):
        self.logger.info("Not implemented yet")
        return
