from Crypto.Cipher import AES
import base64
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
invoke-direct v2, v0, v3, Ljava/io/File;-><init>(Ljava/io/File; Ljava/lang/String;)V
invoke-direct v7, v8, v1, v2, Lbtewtslyl/vmcdkpllfzrvt/u5a48eebb7c1d4;->a(Landroid/content/Context; Ljava/lang/String; Ljava/io/File;)Z
new-instance v3, Ldalvik/system/DexClassLoader;
"""
find_aes_function = (
    r"invoke-direct [vp]\d+, [vp]\d+, [vp]\d+, Ljava/io/File;-><init>\(Ljava/io/File; Ljava/lang/String;\)V\s+"
    r"invoke-direct [vp]\d+, [vp]\d+, [vp]\d+, [vp]\d+, (L[^;]+;->[^\(]+)\(Landroid/content/Context; Ljava/lang/String; Ljava/io/File;\)Z\s+"
    r"new-instance [vp]\d+, Ldalvik/system/DexClassLoader;"
)
"""
new-instance v2, Ljavax/crypto/CipherInputStream;
const-string v3, '7RHkUDPB5fGL4NLPDuehSRjnxYGr0I7KmsqAUwLT1sk='
invoke-direct v4, v3, Lbtewtslyl/vmcdkpllfzrvt/u5a48eebb7c1d4;->a(Ljava/lang/String;)Ljavax/crypto/Cipher;
move-result-object v3
"""

find_aes_key = (
    r"new-instance [vp]\d+, Ljavax/crypto/CipherInputStream;\s+"
    r"const-string [vp]\d+, \"(.*)\"\s+"
    r"invoke-direct [vp]\d+, [vp]\d+, L[^;]+;->[^\(]+\(Ljava/lang/String;\)Ljavax/crypto/Cipher;\s+"
    r"move-result-object [vp]\d+"
)


class LoaderSimpleAes(Unpacker):
    decrypted_payload_path = None

    def __init__(self, apk_object, dvms, output_dir):
        super().__init__(
            "loader.simpleaes",
            "Unpacker for multiple simple unpackers",
            apk_object,
            dvms,
            output_dir,
        )

    def start_decrypt(self):
        self.logger.info("Starting to decrypt")
        self.aes_key = self.find_aes_key()
        if self.aes_key is None:
            return
        self.decrypt_files(self.aes_key)

    def find_aes_key(self):
        asset_filenames = [
            x.replace("assets/", "")
            for x in self.apk_object.get_files()
            if x.startswith("assets/")
        ]
        for d in self.dvms:
            for c in d.get_classes():
                for m in c.get_methods():
                    if (
                        m.get_descriptor() == "(Landroid/content/Context;)V"
                        and m.get_name() == "<init>"
                    ):
                        m_smali = self.get_smali(m)

                        for fname in asset_filenames:
                            if fname in m_smali:
                                self.logger.info("Found method")
                                target_method = m
                                m = re.findall(find_aes_function, m_smali)
                                if len(m) == 0:
                                    continue
                                klass, method = m[0].split("->")
                                target_method = self.find_method(
                                    klass,
                                    method,
                                    "(Landroid/content/Context; Ljava/lang/String; Ljava/io/File;)Z",
                                )
                                if target_method:
                                    aes_key = re.findall(
                                        find_aes_key, self.get_smali(target_method)
                                    )
                                    if aes_key:
                                        return aes_key[0]

        return None

    def decrypt_files(self, aes_key):
        try:
            kk = base64.b64decode(aes_key)
        except Exception as e:
            self.logger.error(e)
            return

        key = kk[:16]
        iv = kk[16:32]
        ai = AES.new(key, AES.MODE_CBC, iv)
        if self.decrypted_payload_path == None:
            out_file = "unpacked.dex"
        else:
            index = re.findall(r"\d+", self.decrypted_payload_path)
            if index:
                ii = int(index[0])
                out_file = f"unpacked{ii+1}.dex"
            else:
                out_file = "unpacked1.dex"

        for filepath in self.apk_object.get_files():
            if not (filepath.startswith("assets") or filepath.startswith("res")):
                continue
            fd = self.apk_object.get_file(filepath)
            dec = ai.decrypt(fd)
            if self.check_and_write_file(dec):
                return True
        return False
