from datetime import datetime
from androguard.core.apk import APK
from arc4 import ARC4
from androguard.core.dex import DEX
import re
from itertools import combinations
from kavanoz.unpack_plugin import Unpacker
from kavanoz.smali_regexes import Regexs
from kavanoz.utils import xor


"""
invoke-virtual v8, v2, Ljava/io/InputStream;->read([B)I
const-string v5, 'bhMIAdCgBYYOymrlRp'
invoke-virtual v5, Ljava/lang/String;->getBytes()[B
move-result-object v5
invoke-static v2, v5, Lorvbreo/ycmgmee;->ZowuWxil([B [B)[B
move-result-object v2
invoke-virtual v8, Ljava/io/InputStream;->close()V
"""

find_xor_key = (
    r"invoke-virtual [vp]\d+, [vp]\d+, L[^;]+;->read\(\[B\)I\s+"
    r"const-string [vp]\d+, \"(.*)\"\s+"
    r"invoke-virtual [vp]\d+, L[^;]+;->getBytes\(\)+\[B\s+"
    r"move-result-object [vp]\d+\s+"
    r"invoke-static [vp]\d+, [vp]\d+, L[^;]+;->([^\(]+)\(\[B \[B\)\[B\s+"
    r"move-result-object [vp]\d+\s+"
    r"invoke-virtual [vp]\d+, L[^;]+;->close\(\)V\s+"
)

find_second_xor_key = (
    r"const-string [vp]\d+, \"(.*)\"\s+"
    r"invoke-virtual [vp]\d+, L[^;]+;->getBytes\(\)+\[B\s+"
    r"move-result-object [vp]\d+\s+"
    r"invoke-static [vp]\d+, [vp]\d+, L[^;]+;->([^\(]+)\(\[B \[B\)\[B\s+"
    r"move-result-object [vp]\d+\s+"
    r"invoke-virtual [vp]\d+, [vp]\d+, L[^;]+;->write\(\[B\)V\s+"
)


class LoaderSesdex(Unpacker):
    regex_class = Regexs()
    rc4_string_var = ""
    first_inner = []
    second_inner = []
    byte_array_data = []
    decrypted_payload_path = None

    def __init__(self, apk_object, dvms, output_dir):
        super().__init__(
            "loader.sesdex",
            "Unpacker for unknown adware malware",
            apk_object,
            dvms,
            output_dir,
        )

    def start_decrypt(self):
        self.second_inner_regex = self.regex_class.get_second_inner_regex()
        self.first_encryption_route = self.regex_class.get_encrytion_route_regex()
        self.key_class_regex = self.regex_class.get_key_class_regex()
        self.logger.info("Starting to decrypt")
        self.xor_key = self.find_xor_key()
        if self.xor_key is None:
            return
        self.decrypt_files(self.xor_key)

        for filepath in self.apk_object.get_files():
            second_xor_key = self.find_second_xor_key()
            if second_xor_key:
                self.decrypt_files(second_xor_key)

    def find_xor_key(self):
        application = self.apk_object.get_attribute_value("application", "name")
        if application == None:
            return None
        # self.logger.info(f"application android:name = {application}")
        application_smali = "L" + application.replace(".", "/") + ";"
        target_method = self.find_method_re(
            application_smali, ".*", "(Ljava/io/InputStream;)Ljava/io/File;"
        )
        if target_method == None:
            return
        sm = self.get_smali(target_method)
        if "ses.dex" not in sm:
            return
        m = re.findall(find_xor_key, sm)
        if len(m) == 1:
            return bytes(m[0][0].encode("utf-8"))
        else:
            return None

    def find_second_xor_key(self):
        if self.decrypted_payload_path == None:
            return
        with open(self.decrypted_payload_path, "rb") as fp:
            d = fp.read()
            dvm = DEX(d)
            for c in dvm.get_classes():
                if c.get_superclassname() == "Landroid/app/Application;":
                    for m in c.get_methods():
                        if m.get_name() == "onCreate":
                            sm = self.get_smali(m)
                            matches = re.findall(find_second_xor_key, sm)
                            if matches:
                                return matches[0][0].encode("utf-8")

    def decrypt_files(self, xor_key):
        for filepath in self.apk_object.get_files():
            if not (filepath.startswith("assets") or filepath.startswith("res")):
                continue
            fd = self.apk_object.get_file(filepath)
            dec = xor(fd, xor_key)
            if self.check_and_write_file(dec):
                return True
        return False
