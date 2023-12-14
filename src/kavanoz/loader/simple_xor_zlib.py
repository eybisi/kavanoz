import base64
import re
from kavanoz.unpack_plugin import Unpacker
from kavanoz.utils import xor
import zlib


class LoaderSimpleXorZlib(Unpacker):
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
        self.decrypt_files()

    def decrypt_files(self):
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
            if not filepath.startswith("assets"):
                continue
            fd = self.apk_object.get_file(filepath)
            if len(fd) < 8:
                return False
            if fd[4] == 0x78 and fd[5] == 0x9C:
                try:
                    dec = zlib.decompress(fd[4:])
                except Exception as e:
                    self.logger.error(e)
                    return False
            else:
                xor_k = fd[4]
                zlib_d = fd[5:]
                dec = xor(zlib_d, xor_k.to_bytes(1, "little"))
                if dec[:2] != b"\x78\x01":
                    return
                try:
                    dec = zlib.decompress(dec)
                except Exception as e:
                    self.logger.error(e)
                    return

            try:
                dec = base64.b64decode(dec)
            except Exception as e:
                self.logger.error(e)
                return
            if self.check_and_write_file(dec):
                return True
        return False
