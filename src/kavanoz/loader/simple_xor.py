import re
from kavanoz.unpack_plugin import Unpacker
from kavanoz.utils import xor

"""
invoke-direct v10, v14, v15, Ljava/lang/Long;-><init>(J)V
const/4 v9, 0
array-length v13, v4
if-ge v9, v13, +03fh
aget-byte v13, v4, v9
const-string v14, "pAinaTuyPSZcNjEbewHmUaUiFLzjnb"
invoke-virtual v14, Ljava/lang/String;->getBytes()[B
move-result-object v14
invoke-virtual v10, Ljava/lang/Long;->longValue()J
move-result-wide v16
move-wide/from16 v0, v16
long-to-int v15, v0
aget-byte v14, v14, v15
xor-int/2addr v13, v14
int-to-byte v13, v13
aput-byte v13, v8, v9
"""

find_xor_key = (
    r"const/4 [vp]\d+, 0\s+"
    r"array-length [vp]\d+, [vp]\d+\s+"
    r"if-ge [vp]\d+, [vp]\d+, \+03fh\s+"
    r"aget-byte [vp]\d+, [vp]\d+, [vp]\d+\s+"
    r"const-string [vp]\d+, \"(.*)\"\s+"
    r"invoke-virtual [vp]\d+, L[^;]+;->getBytes\(\)+\[B\s+"
    r"move-result-object [vp]\d+\s+"
    r"invoke-virtual [vp]\d+, L[^;]+;->longValue\(\)J\s+"
)


class LoaderSimpleXor(Unpacker):
    decrypted_payload_path = None

    def __init__(self, apk_object, dvms, output_dir):
        super().__init__(
            "loader.simplexor",
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
        application = self.apk_object.get_attribute_value("application", "name")
        if application == None:
            return None
        # self.logger.info(f"application android:name = {application}")
        application_smali = "L" + application.replace(".", "/") + ";"
        target_method = self.find_method(application_smali, "attachBaseContext")
        if target_method == None:
            return
        sm = self.get_smali(target_method)
        m = re.findall(find_xor_key, sm)
        if len(m) == 1:
            return bytes(m[0].encode("utf-8"))
        else:
            return

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
