import re
from kavanoz.unpack_plugin import Unpacker
from kavanoz.utils import xor


# const/16 v0, 0xc
# new-array v0, v0, [B
# fill-array-data v0, :array_8
# return-object v0
byte_array_function = (
    r"const/16 [vp]\d+, \d+\s+"
    r"new-array [vp]\d+, [vp]\d+, \[B\s+"
    r"fill-array-data [vp]\d+.*\s+"
    r"return-object [vp]\d+"
)


class LoaderPr0nLocker(Unpacker):
    decrypted_payload_path = None

    def __init__(self, apk_object, dvms, output_dir):
        super().__init__(
            "loader.pr0nlocker", "Unpacker for pr0nlocker", apk_object, dvms, output_dir
        )

    def start_decrypt(self):
        self.logger.info("Starting to decrypt")
        self.xor_key = self.find_xor_key()
        if self.xor_key is None:
            return
        self.decrypt_files(bytes(self.xor_key))

    def find_xor_key(self):
        """There is distinct string decryption function in the code takes float and string as input
        and returns string as output. We can find the string decryption function and then find the
        byte array function that is used to decrypt the asset files. We can then find the byte array
        data and use it as xor key to decrypt the asset files.
        """

        found_str_decryptor = False
        str_decryptor_class = None
        for d in self.dvms:
            for c in d.get_classes():
                for m in c.get_methods():
                    if (
                        m.get_descriptor()
                        == "(Ljava/lang/Float; Ljava/lang/String;)Ljava/lang/String;"
                    ):
                        found_str_decryptor = True
                        str_decryptor_class = c

        if not found_str_decryptor or str_decryptor_class is None:
            return None

        for m in str_decryptor_class.get_methods():
            if m.get_descriptor() == "()[B":
                self.logger.info("Found byte array function")
                smali = self.get_smali(m)
                match = re.findall(byte_array_function, smali)
                if match:
                    self.logger.info("Found byte array function")
                    array_data = self.get_array_data(m)
                    return array_data[0]
        return None

    def decrypt_files(self, xor_key: bytes):
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
            # Assets have 4 files, 1 html,1 json config, 2 dex
            if not (filepath.startswith("assets") or filepath.startswith("res")):
                continue
            fd = self.apk_object.get_file(filepath)
            dec = xor(fd, xor_key)
            if self.check_and_write_file(dec):
                self.logger.info("Found encrypted file: %s", filepath)
                self.logger.info(
                    "Writing decrypted file to: %s", self.decrypted_payload_path
                )
            else:
                try:
                    decrypted = dec.decode("utf-8")
                    if decrypted.startswith("<!DOCTYPE html>"):
                        self.logger.info("Found html file:")
                        calculated_name = self.calculate_name(dec)
                        calculated_name = calculated_name.replace(".dex", ".html")
                        self.logger.info(
                            "Writing decrypted file to: %s", calculated_name
                        )
                        with open(calculated_name, "w") as f:
                            f.write(decrypted)
                    else:
                        self.logger.info("Found config file:")
                        calculated_name = self.calculate_name(dec)
                        calculated_name = calculated_name.replace(".dex", ".json")
                        self.logger.info(
                            "Writing decrypted file to: %s", calculated_name
                        )
                        with open(calculated_name, "w") as f:
                            f.write(decrypted)

                except:
                    pass
        return False
