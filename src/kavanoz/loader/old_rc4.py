from androguard.core.apk import APK
from androguard.core.dex import DEX
import re
from arc4 import ARC4
from kavanoz.unpack_plugin import Unpacker


class LoaderOldRc4(Unpacker):
    def __init__(self, apk_obj, dvms, output_dir):
        super().__init__(
            "loader.rc4.v2",
            "Unpacker old rc4 based variants",
            apk_obj,
            dvms,
            output_dir,
        )

    def start_decrypt(self, native_lib: str = ""):
        self.logger.info("Starting to decrypt")
        self.decrypted_payload_path = None
        application_oncreate = self.find_application_oncreate()
        if not application_oncreate:
            return
        rc4_caller = self.find_caller_rc4_init(application_oncreate)
        if not rc4_caller:
            return
        rc4_inits = self.get_rc4_init_from_caller(rc4_caller)
        for rc4_init in rc4_inits:
            rc4_keys = self.get_rc4_key(rc4_init)
            for rc4_key in rc4_keys:
                x = self.brute_assets(rc4_key)
                if x != None:
                    return

    def get_rc4_key(self, rc4_init_function):
        klass_name, method_name = rc4_init_function.split("->")
        m = self.find_method(klass_name, method_name, descriptor="()V")
        if m:
            self.logger.info(m.get_name())
            array_data = self.get_array_data(m)
            if len(array_data) > 1:
                self.logger.info("Found multiple array data, might be wrong function")
            return array_data
        return []

    def get_rc4_init_from_caller(self, class_func_str) -> list:
        klass_name, method_name = class_func_str.split("->")
        m = self.find_method(klass_name, method_name, "(Landroid/app/Application;)V")
        if m == None:
            return []
        self.logger.info("Found rc4 init method")
        """
        public void xVKoMuDKBel(Application application) {
            yQuzIA();

        invoke-direct v11, Lcom/tnmwagts/rmorecegr/MPqJcHURCv;->yQuzIA()V
        """
        smali_str = self.get_smali(m)
        # find functions without parameters.
        match = re.findall(r"invoke-direct [vp]\d+, (L[^;]+;->[^\s]+)\(\)V", smali_str)
        if len(match) == 0:
            self.logger.info("Unable to extract variable from target_method")
            self.logger.info("Exiting ...")
            return []
        if len(match) == 1:
            self.logger.info(f"Found variable ! : {match[0]}")
        else:
            self.logger.info("Found multiple functions to call rc4_init 🤔")
        return match
        return []

    def find_application_oncreate(self):
        application = self.apk_object.get_attribute_value("application", "name")
        if application == None:
            return None
        # self.logger.info(f"application android:name = {application}")
        application_smali = "L" + application.replace(".", "/") + ";"
        return self.find_method(application_smali, "onCreate")

    def find_caller_rc4_init(self, target_method):
        """
        invoke-virtual v2, v6, Lcom/tnmwagts/rmorecegr/MPqJcHURCv;->xVKoMuDKBel(Landroid/app/Application;)V
        """
        smali_str = self.get_smali(target_method)
        match = re.findall(
            r"invoke-virtual [vp]\d+, [vp]\d+, (L[^;]+;->[^\s]+)\(Landroid/app/Application;\)V\s+",
            smali_str,
        )
        if len(match) == 0:
            self.logger.info("Unable to extract variable from target_method")
            self.logger.info("Exiting ...")
            return None
        if len(match) == 1:
            self.logger.info(f"Found variable ! : {match[0]}")
            return match[0]
        else:
            self.logger.info("Something is wrong .. 🤔")
            self.logger.info("Found multiple ?? : {match}")
            return None

    def brute_assets(self, key: bytes):
        self.logger.info("Starting brute-force")
        asset_list = self.apk_object.get_files()
        for filepath in asset_list:
            f = self.apk_object.get_file(filepath)
            if self.solve_encryption(f, key, filepath):
                self.logger.info(f"Decryption finished! {self.decrypted_payload_path}")
                return self.decrypted_payload_path
        self.logger.info(f"No valid file found for {key}")
        return None

    def solve_encryption(self, file_data, key: bytes, filepath: str):
        arc4 = ARC4(bytes(key))
        filesize = int.from_bytes(file_data[0:4], byteorder="little")
        if filesize > len(file_data):
            return False
        decrypted = arc4.decrypt(file_data[4:])
        decrypted = decrypted[:filesize]
        if self.check_and_write_file(decrypted):
            return True
        return False
