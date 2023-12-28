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
array-length v0, v3
new-array v0, v0, [B
const/4 v1, 0
array-length v2, v3
if-ge v1, v2, +c
aget-byte v2, v3, v1
xor-int/lit8 v2, v2, -43
int-to-byte v2, v2
aput-byte v2, v0, v1
add-int/lit8 v1, v1, 1
goto -c
return-object v0
"""

find_xor_key = r"xor-int/lit8 [vp]\d+, [vp]\d+, (-?\d+)"
"""
invoke-virtual v0, v2, Ljava/io/InputStream;->read([B)I
invoke-virtual v0, Ljava/io/InputStream;->close()V
invoke-static v2, Lcom/squareup/leakcanary/gutG;->XdB([B)[B
move-result-object v0
invoke-virtual v6, v0, Ljava/io/FileOutputStream;->write([B)V
invoke-virtual v6, Ljava/io/FileOutputStream;->close()V
"""
find_xor_function = (
    r"invoke-virtual [vp]\d+, [vp]\d+, Ljava/io/InputStream;->read\(\[B\)I\s+"
    r"invoke-virtual [vp]\d+, Ljava/io/InputStream;->close\(\)V\s+"
    r"invoke-static [vp]\d+, (L[^;]+;->[^\(]+)\(\[B\)\[B\s+"
    r"move-result-object [vp]\d+\s+"
    r"invoke-virtual [vp]\d+, [vp]\d+, Ljava/io/FileOutputStream;->write\(\[B\)V\s+"
)


class LoaderSimpleXor2(Unpacker):
    decrypted_payload_path = None

    def __init__(self, apk_object, dvms, output_dir):
        super().__init__(
            "loader.simplexor2",
            "Unpacker for multiple simple unpackers",
            apk_object,
            dvms,
            output_dir,
        )

    def start_decrypt(self):
        self.logger.info("Starting to decrypt")
        self.xor_key = self.find_xor_key()
        if self.xor_key is None:
            return
        self.decrypt_files(self.xor_key)

    def find_xor_key(self):
        asset_filenames = [
            x.replace("assets/", "")
            for x in self.apk_object.get_files()
            if x.startswith("assets/")
        ]
        for d in self.dvms:
            for c in d.get_classes():
                for m in c.get_methods():
                    if (
                        m.get_descriptor()
                        == "(Landroid/content/Context;)Ljava/io/File;"
                    ):
                        m_smali = self.get_smali(m)
                        for fname in asset_filenames:
                            if fname in m_smali:
                                matches = re.findall("[a-f0-9]+\.dex", m_smali)
                                if len(matches) == 0:
                                    self.logger.info("no match")
                                    return
                                self.logger.info("Found method")
                                target_method = m
                                m = re.findall(find_xor_function, m_smali)
                                klass, method = m[0].split("->")
                                target_method = self.find_method(klass, method)
                                if target_method:
                                    xor_key = re.findall(
                                        find_xor_key, self.get_smali(target_method)
                                    )
                                    if xor_key:
                                        n = int(xor_key[0])
                                        n = n & 0xFF
                                        self.logger.info(f"Found single xor key : {n}")
                                        return n.to_bytes(1, "little")
        return None

    def decrypt_files(self, xor_key):
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
            dec = xor(fd, xor_key)
            if self.check_and_write_file(dec):
                return True
        return False
