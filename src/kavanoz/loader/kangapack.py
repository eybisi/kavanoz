from androguard.core.apk import APK
from kavanoz.unpack_plugin import Unpacker
from Crypto.Cipher import AES
from kavanoz.unpack_plugin import Unpacker
import lief


class LoaderKangaPack(Unpacker):
    """
    ref: https://cryptax.medium.com/inside-kangapack-the-kangaroo-packer-with-native-decryption-3e7e054679c4
    encrypted file is appended to end of classes.dex
    aes decryption key/iv is in native library used with openssl evp api, keys are exported
    """

    def __init__(self, apk_obj, dvms, output_dir):
        super().__init__(
            "loader.kangapack", "Unpacker for kangapack", apk_obj, dvms, output_dir
        )

    def start_decrypt(self, native_lib: str = ""):
        # Get encrypted payload
        classes_dex = lief.DEX.parse(list(self.apk_object.get_dex()))
        dex_headers = classes_dex.header
        link_off, link_size = dex_headers.link
        enc_offset = 0
        if link_off == 0 and link_size == 0:
            off, size = dex_headers.data
            if dex_headers.file_size > off + size:
                enc_offset = off + size
        if enc_offset == 0:
            return

        enc_payload = self.apk_object.get_dex()[enc_offset:]
        payload_size = enc_payload[len(enc_payload) - 4 :]
        enc_payload = enc_payload[: len(enc_payload) - 4]
        native_libs = [
            filename
            for filename in self.apk_object.get_files()
            if filename.startswith("lib/arm64-v8a/libapk")
        ]
        if len(native_libs) == 0:
            self.logger.info("No native lib 😔")
            return
        if len(native_libs) != 1:
            self.logger.info("Not sure this is kangapack but continue anyway")

        fname = native_libs[0].split("/")[-1]
        self.target_lib = fname
        elf_bin = lief.ELF.parse(
            list(self.apk_object.get_file(f"lib/arm64-v8a/{self.target_lib}"))
        )
        for sym in elf_bin.exported_symbols:
            if sym.name == "AES_SECRET_KEY":
                rel = elf_bin.get_relocation(sym.value)
                # get lots of bytes then split by null byte :(
                str_arr = elf_bin.get_content_from_virtual_address(rel.addend, 40)
                an = str_arr[: str_arr.index(0)]
                secret_key = "".join(chr(x) for x in an).encode()
                iv = secret_key
                cipher = AES.new(secret_key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(enc_payload)
                if self.check_and_write_file(decrypted):
                    self.logger.info(f"Decrypted dex with key {secret_key}")
                    return True
        return False

    def lazy_check(self, apk_object: APK, dvms: "list[DEX]") -> bool:
        dex_bytes = apk_object.get_dex()
        if len(dex_bytes) > 0:
            try:
                classes_dex = lief.DEX.parse(list(dex_bytes))
            except Exception as e:
                # print(e)
                return False
            dex_headers = classes_dex.header
            link_off, link_size = dex_headers.link

            if link_off == 0 and link_size == 0:
                off, size = dex_headers.data
                if dex_headers.file_size > off + size:
                    return True
        return False
