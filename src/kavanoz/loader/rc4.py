from datetime import datetime
from androguard.core.apk import APK
from arc4 import ARC4
from androguard.core.dex import DEX
import re
from itertools import combinations
from kavanoz.unpack_plugin import Unpacker
from kavanoz.smali_regexes import Regexs
import string


class LoaderRc4(Unpacker):
    regex_class = Regexs()
    rc4_string_var = ""
    first_inner = []
    second_inner = []
    byte_array_data = []
    decrypted_payload_path = None

    def __init__(self, apk_object, dvms, output_dir):
        super().__init__(
            "loader.rc4.v1", "Unpacker rc4 based variants", apk_object, dvms, output_dir
        )

    def start_decrypt(self):
        self.second_inner_regex = self.regex_class.get_second_inner_regex()
        self.first_encryption_route = self.regex_class.get_encrytion_route_regex()
        self.key_class_regex = self.regex_class.get_key_class_regex()
        self.logger.info("Starting to decrypt")
        self.attach_class = self.find_attach_class()
        if self.attach_class is None:
            return

        all_possible_rc4_keys = self.find_rc4_keys_from_attach_class(self.attach_class)
        self.logger.info(f"all possible keys : {all_possible_rc4_keys}")
        if all_possible_rc4_keys:
            if self.decrypt_files(all_possible_rc4_keys):
                # More stages
                if not self.is_really_unpacked():
                    if self.bruteforce_all_strings():
                        self.logger.info("Multiple stage is decrypted")
        else:
            if self.bruteforce_all_strings():
                self.logger.info("Multiple stage is decrypted")

    def bruteforce_all_strings(self):
        if not self.is_really_unpacked():
            all_possible_rc4_keys = list(
                filter(
                    lambda x: x != None,
                    self.find_all_strings_from_application_class(self.dvms[-1]),
                )
            )
            if self.decrypt_files(all_possible_rc4_keys):
                return self.bruteforce_all_strings()
            else:
                return False
        else:
            return True

    def find_attach_class(self):
        application = self.apk_object.get_attribute_value("application", "name")
        if application == None:
            return None
        # self.logger.info(f"application android:name = {application}")
        application_smali = "L" + application.replace(".", "/") + ";"
        target_method = self.find_method(application_smali, "attachBaseContext")
        return target_method

    def find_application_init(self):
        application = self.apk_object.get_attribute_value("application", "name")
        if application == None:
            return None
        # self.logger.info(f"application android:name = {application}")
        application_smali = "L" + application.replace(".", "/") + ";"
        target_method = self.find_method(application_smali, "<init>")
        return target_method

    def find_rc4_keys_from_attach_class(self, target_method):
        smali_str = self.get_smali(target_method)
        match = self.first_encryption_route.findall(smali_str)
        if len(match) == 0:
            self.logger.info(f"Unable to extract variable from {target_method}")
            self.logger.info("Exiting ...")

        if len(match) == 1:
            # self.logger.info(f'HMM : {match[0]}')
            method = self.find_method(target_method.get_class_name(), match[0])
            if method == None:
                return
            smali_str = self.get_smali(method)
            # self.logger.info(smali_str)
            key_class = self.key_class_regex.findall(smali_str)
            if len(key_class) != 1:
                return
            self.logger.info(f"Key class : {key_class[0]}")
            klass = self.find_class_in_dvms(key_class[0][2])
            if klass == None:
                return
            return self.find_rc4_keys_from_klass_fields(klass)

    def find_all_strings(self, dvm: DEX) -> set:
        all_rc4_keys = set()
        for klass in dvm.get_classes():
            all_rc4_keys.update(self.find_rc4_keys_from_klass_fields(klass))
        return all_rc4_keys

    def find_all_strings_from_application_class(self, dvm: DEX) -> set:
        application = self.apk_object.get_attribute_value("application", "name")
        if application == None:
            return None
        application_smali = "L" + application.replace(".", "/") + ";"
        klass = self.find_class_in_dvms(application_smali)
        all_rc4_keys = set()
        all_rc4_keys.update(self.find_rc4_keys_from_klass_fields(klass))
        return all_rc4_keys

    def find_rc4_keys_from_klass_fields(self, klass) -> set:
        all_possible_rc4_keys = set()
        for field in klass.get_fields():
            rc4_string_variable = None
            if field.get_descriptor() != "Ljava/lang/String;":
                continue
            if field.get_init_value() != None and field.get_init_value != "":
                self.logger.info(
                    f"Found static key : {field.get_init_value().get_value()}"
                )
                static_rc4_string = field.get_init_value().get_value()
                r = set()
                r.add(static_rc4_string.encode())
                return r
            else:
                if (
                    "0x0" == field.get_access_flags_string()
                    or "protected final" == field.get_access_flags_string()
                    or "" == field.get_access_flags_string()
                ):
                    rc4_string_variable = field.get_name()
            if rc4_string_variable is not None:
                self.regex_class.set_first_inner_regex(rc4_string_variable)
                all_possible_rc4_keys.update(self.get_key_from_init(klass))
        return all_possible_rc4_keys

    def get_key_from_init(self, klass) -> set:
        """
        String field is calculated with two inner functions.
        Example :
            - String SAsDiYdEsXlNsTnXkKoYoSmZp = derivetrouble(new String[98]);
            - static String derivetrouble(String[] strArray) {
                return leaveangry();
              }
            - public static String leaveangry() {
                    byte[] bArr = {11, 63, 45, 21};
                    byte[] bArr2 = new byte[4];
                    byte[] bArr3 = {79};
                    while (i8 < 4) {
                        bArr2[i8] = (byte) (bArr[i8] ^ bArr3[i8 % 1]);
                        i8++;
                    }
                    return new String(bArr2);
                }
        We try to find second inner function that generates rc4 key
        """
        possible_rc4_keys = set()
        string_gen_0 = []
        klass_name = klass.get_name()
        init_method = self.find_method(klass_name, "<init>")
        if not init_method:
            return possible_rc4_keys
        smali_str = self.get_smali(init_method)
        for key, regex in self.regex_class.get_first_inner_regexs().items():
            string_gen_0 = regex.findall(smali_str)
            if string_gen_0:
                break
        if string_gen_0:
            self.logger.info(f"First inner function: {string_gen_0[0]}")
            string_gen_1 = []
            # Find function that uses first found function
            first_method = self.find_method(klass_name, string_gen_0[0])
            if not first_method:
                return possible_rc4_keys
            smali_str = self.get_smali(first_method)
            string_gen_1 = self.second_inner_regex.findall(smali_str)
            if not string_gen_1:
                self.logger.info(
                    f"Unable to extract second inner function from {first_method.get_name()}"
                )
                self.logger.info("Checking if we are already in the last function")
                rc4_keys = self.generate_rc4_keys_from_method(first_method)
                possible_rc4_keys.update(rc4_keys)

            else:
                self.logger.info(f"Second inner function: {string_gen_1[0]}")
                if string_gen_1:
                    second_method = self.find_method(klass_name, string_gen_1[0])
                    if second_method:
                        rc4_keys = self.generate_rc4_keys_from_method(second_method)
                        possible_rc4_keys.update(rc4_keys)
        else:
            self.logger.info("Unable to extract first inner function")

        return possible_rc4_keys

    def generate_rc4_keys_from_method(self, method) -> set:
        """
        Extract array data from target method. Generaly packer generates rc4 key from two array data.
        Or defines constant string.
        First regex captures string,
        """
        # self.logger.info(self.get_smali(method))
        smali = self.get_smali(method)
        match = re.findall(
            r"const-string [vp]\d+, \'(.*?)\'\s+" r"return-object [vp]\d+", smali
        )
        if len(match) == 1:
            self.logger.info(match)
            # self.decrypt_files([match[0]])
            r = set()
            k = match[0]
            if type(k) is bytes or type(k) is str:
                r.add(k)
                return r

        arrays_in_method = self.get_array_data(method)
        if len(arrays_in_method) < 2:
            return set()
        if len(arrays_in_method) > 2:
            self.logger.info(
                f"We have {len(self.byte_array_data)} byte arrays, so gonna brute force little bit"
            )
        if len(arrays_in_method) == 2:
            self.logger.info(
                f"RC4 key generators : {arrays_in_method[0]} - {arrays_in_method[1]}"
            )
        rc4_keys = self.get_all_rc4_keys(arrays_in_method)
        return rc4_keys

    def decrypt_files(self, rc4key):
        for filepath in self.apk_object.get_files():
            if filepath.endswith(".json"):
                fd = self.apk_object.get_file(filepath)
                for rc4k in rc4key:
                    if len(rc4k) > 0:
                        dede = ARC4(rc4k)
                        dec = dede.decrypt(fd[:8])
                        if self.check_header(dec):
                            dede = ARC4(rc4k)
                            dec = dede.decrypt(fd)
                            if self.check_and_write_file(dec):
                                self.logger.info(
                                    f"Decrypted dex is from {filepath} with key {rc4k}"
                                )
                                return True
        return False

    def get_all_rc4_keys(self, keys: list) -> set:
        rc4_key = set()
        if len(keys) > 2:
            # combinartion of keys
            comb = combinations(keys, 2)
            rc4_key = set()
            for k in comb:
                rc4_key.add(self.generate_rc4_key(k[0], k[1], True))
            for k in keys:
                rc4_key.add(bytes(k))
        else:
            rc4_key.add(self.generate_rc4_key(keys[0], keys[1]))
            rc4_key.add(self.generate_rc4_key(keys[0], keys[1], True))
        return rc4_key

    def generate_rc4_key(self, key0, key1, without_arrange=False):
        big_key = key0 if len(key0) > len(key1) else key1
        smol_key = key0 if len(key0) < len(key1) else key1
        rc4_key = bytearray()
        for i in range(len(big_key)):
            zz = big_key[i] ^ smol_key[i % len(smol_key)]
            rc4_key.append(zz)

        if without_arrange:
            rc4_key = bytearray()
            for i in range(len(key0)):
                rc4_key.append(key0[i] ^ key1[i % len(key1)])
            return bytes(rc4_key)
        return bytes(rc4_key)
