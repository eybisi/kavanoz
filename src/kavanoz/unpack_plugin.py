from androguard.core.apk import APK
import re
from androguard.core.dex import DEX, EncodedMethod, ClassDefItem
import time
import io
import zipfile
import hashlib
import zlib
from kavanoz.utils import dex_headers, pkzip_headers, zlib_headers
from loguru import logger
import os


class Unpacker:
    tag = "DefaultUnpackPlugin"
    name = "DefaultUnpackName"

    def __init__(
        self,
        tag: str,
        name: str,
        apk_object: APK,
        dvms: list[DEX],
        output_dir,
    ):
        """Default unpacking plugin"""
        self.tag = tag
        self.name = name
        self.decrypted_payload_path = None
        self.logger = logger
        self.apk_object = apk_object
        self.dvms = list(filter(self.filter_dvms, dvms))
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = os.getcwd()

    @staticmethod
    def filter_dvms(dvm):
        if dvm.classes == None:
            return False
        return True

    def is_packed(self) -> bool:
        """Checks if apk is packed by checking components defined in AndroidManifest.xml is present in dex

        :returns ispacked: Is apk packed
        :rtype:bool
        """
        ispacked = False
        not_found_counter = 0
        act_serv_recv = (
            self.apk_object.get_activities()
            + self.apk_object.get_receivers()
            + self.apk_object.get_services()
        )
        for component in act_serv_recv:
            if component:
                for dex in self.dvms:
                    try:
                        dex_classes = dex.get_classes_names()
                    except Exception as e:
                        continue
                    clas_name = "L" + component.replace(".", "/") + ";"
                    if clas_name in dex_classes:
                        break
                else:
                    not_found_counter += 1
        if len(act_serv_recv) == 0:
            return False
        score = not_found_counter / len(act_serv_recv)
        self.logger.info(f"Packed : Score : {score}")
        if score > 0.80:
            ispacked = True
        else:
            # Lets check if MainActivity is present
            res = self.apk_object.get_main_activity()
            if res:
                for dex in self.dvms:
                    try:
                        dex_classes = dex.get_classes_names()
                    except Exception as e:
                        continue
                    clas_name = "L" + res.replace(".", "/") + ";"
                    if clas_name in dex_classes:
                        break
                else:
                    ispacked = True
        return ispacked

    def is_really_unpacked(self) -> bool:
        """Adds decrypted dex file as dvm and checks if its still packed or not"""
        if not self.decrypted_payload_path:
            return False
        # add last dvm
        with open(self.decrypted_payload_path, "rb") as fp:
            self.dvms.append(DEX(fp.read()))
        return not self.is_packed()

    def get_tag(self) -> str:
        return self.tag

    def get_name(self) -> str:
        return self.name

    def __str__(self):
        return f"Name: {self.name}\nTag: {self.tag}"

    @staticmethod
    def get_smali(target_method: EncodedMethod) -> str:
        """
        Get smali represantation of target_method
        """
        smali_str = ""
        for ins in target_method.get_instructions():
            smali_str += f"{ins.get_name()} {ins.get_output()}\n"
        return smali_str

    @staticmethod
    def get_array_data(target_method: EncodedMethod) -> list:
        """
        Get array data from target_method. This is done via parsing instructions
        """
        barrays = []
        for ins in target_method.get_instructions():
            if ins.get_name() == "fill-array-data-payload":
                # androguard bug
                # 00 03 01 00 07 00 00 00 5e 5a 6a 71 5e 6c 74 00
                # Following code has wrong data, it retusn 0c,00 instead of 0c 00 00
                # 00 03 01 00 02 00 00 00 0c 00
                # ins.get_data also return with \x00 appended, we dont need that
                raw_data = list(ins.get_raw())
                # print(ins.get_raw())
                # print(ins.get_hex())
                # print(ins.get_data())
                data_size = raw_data[4]
                barray = bytearray(raw_data[8 : 8 + data_size])
                barrays.append(barray)
        return barrays

    def find_method(
        self, klass_name: str, method_name: str, descriptor: str = ""
    ) -> EncodedMethod:
        """
        Find method in dvms via class name and method name. Descriptor is optional
        :returns EncodedMethod of found method
        """
        for dvm in self.dvms:
            c = dvm.get_class(klass_name)
            if c != None:
                methods = c.get_methods()
                for method in methods:
                    if method.get_name() == method_name:
                        if descriptor == "":
                            return method
                        else:
                            if method.get_descriptor() == descriptor:
                                return method
        return None

    def find_method_re(
        self, klass_name: str, method_name: str, descriptor: str = ""
    ) -> EncodedMethod:
        for dvm in self.dvms:
            c = dvm.get_class(klass_name)
            if c != None:
                methods = c.get_methods()
                for method in methods:
                    if len(re.findall(method_name, method.get_name())) > 1:
                        if descriptor == "":
                            return method
                        else:
                            if method.get_descriptor() == descriptor:
                                return method
        return None

    def find_class_in_dvms(self, klass_name: str) -> ClassDefItem:
        """Search class name in dvms and return first instance"""
        for dvm in self.dvms:
            c = dvm.get_class(klass_name)
            if c != None:
                return c
        return None

    @staticmethod
    def find_method_in_class_m(klass, method_name):
        """Find method in klass instance."""
        methods = klass.get_methods()
        for method in methods:
            if method.get_name() == method_name:
                return method
        return None

    def lazy_check(self, apk_object: APK, dvms: "list[DEX]") -> bool:
        """Check if this plugin should run. This method shouldn't be heavy."""
        return True

    def calculate_name(self, file_data) -> str:
        """Calculate external dex file name from file data by taking md5 hash of it"""
        m = hashlib.md5(file_data).hexdigest()
        return f"external-{m[:8]}.dex"

    def check_header(self, fd) -> bool:
        """Check if given data contains dex/pkzip/zlib headers"""
        if len(fd) > 7 and fd[:8] in dex_headers:
            return True
        elif len(fd) > 3 and fd[:4] in pkzip_headers:
            return True
        elif len(fd) > 1 and fd[:2] in zlib_headers:
            return True
        return False

    def check_and_write_file(self, dec) -> bool:
        """
        Check headers and write extracted dex to output_dir, if output_dir is empty save to current path. ZIP/Zlib streams is decompressed and first instance of dex file is written.
        """
        if dec[:8] in dex_headers:
            self.decrypted_payload_path = os.path.join(
                self.output_dir, self.calculate_name(dec)
            )
            self.logger.success(
                f"Decryption succesfull! Output dex : {self.decrypted_payload_path}"
            )
            with open(self.decrypted_payload_path, "wb") as fp:
                fp.write(dec)
            return True
        elif dec[:4] in pkzip_headers:
            self.logger.success(f"Decryption succesfull!\t Found zip file")
            with zipfile.ZipFile(io.BytesIO(dec), "r") as drop:
                for file in drop.filelist:
                    with drop.open(file.filename) as f:
                        zip_files_ex = f.read(8)
                        f.seek(0)
                        if zip_files_ex in dex_headers:
                            self.logger.info(
                                f"Extracting dex from zip file. Output dex : {self.decrypted_payload_path}"
                            )
                            file_data = f.read()
                            self.decrypted_payload_path = os.path.join(
                                self.output_dir, self.calculate_name(dec)
                            )
                            with open(self.decrypted_payload_path, "wb") as fp:
                                fp.write(file_data)
                            return True
        elif dec[:2] in zlib_headers:
            try:
                decrypted = zlib.decompress(dec)
            except Exception as e:
                self.logger.error(e)
                return False
            if decrypted[:8] in dex_headers:
                self.decrypted_payload_path = os.path.join(
                    self.output_dir, self.calculate_name(decrypted)
                )
                self.logger.success(f"Decryption succesfull!\t Found zlib file")
                with open(self.decrypted_payload_path, "wb") as fp:
                    fp.write(decrypted)
                return True
        return False

    def main(self, native_lib: str = "") -> dict:
        """
        Starting point for each plugin. Calls lazy_check then starts start_decrypt. Returns dict of result that contains status, output_file, plugin name and plugin tag
        """
        start_time = time.time()

        result = {}
        result["name"] = self.get_name()
        result["tag"] = self.get_tag()
        if not self.lazy_check(self.apk_object, self.dvms):
            result["status"] = "success" if self.get_status() else "fail"
            return result
        # try:
        o = self.start_decrypt()
        # except Exception as e:
        #    result["error"] = str(e)
        #    result["status"] = "error"
        #    return result

        result["status"] = "success" if self.get_status() else "fail"
        if self.get_status():
            result["output_file"] = self.get_path()
        end_time = time.time()

        self.logger.info(f"total analysis time = {end_time-start_time}")
        return result

    def get_status(self) -> bool:
        """
        Get decryption status by checking decrypted_payload_path
        """
        return self.decrypted_payload_path != None

    def get_path(self) -> str:
        """
        Get decrypted_payload_path
        """
        return self.decrypted_payload_path

    def start_decrypt(self):
        """
        Start decryption routine. This should be overwritten
        """
        pass
