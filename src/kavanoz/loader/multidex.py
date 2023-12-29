from androguard.core.apk import APK
import zlib
from androguard.core.dex import DEX, EncodedMethod
import re
import ctypes
import string
from kavanoz import utils
from kavanoz.unpack_plugin import Unpacker


def unsigned_rshift(val, n):
    unsigned_integer = val % 0x100000000
    return unsigned_integer >> n


def unsigned_lshift(val, n):
    unsigned_integer = val % 0x100000000
    return unsigned_integer << n


class LoaderMultidex(Unpacker):
    ProtectKey = ""

    def __init__(self, apk_obj, dvms, output_dir):
        super().__init__(
            "loader.multidex",
            "Unpacker for multidex variants",
            apk_obj,
            dvms,
            output_dir,
        )

    def start_decrypt(self, native_lib: str = ""):
        self.logger.info("Starting to decrypt")
        z = self.apk_object.get_android_manifest_xml()
        if z != None:
            f = z.find("application")
            childs = f.getchildren()
            self.ProtectKey = None
            for child in childs:
                if child.tag == "meta-data":
                    if (
                        child.attrib["{http://schemas.android.com/apk/res/android}name"]
                        == "ProtectKey"
                    ):
                        self.ProtectKey = child.attrib[
                            "{http://schemas.android.com/apk/res/android}value"
                        ]
                        self.logger.info(f"Found protect key {self.ProtectKey}")
            if self.ProtectKey != None:
                if self.find_decrypt_protect_arrays():
                    self.logger.info("Found key in manifest/xor")
                    return

        self.decrypted_payload_path = None
        zip_function = self.find_zip_function()
        if zip_function is not None:
            _function, dvm = zip_function
            variable = self.extract_variable_from_zip(_function, dvm)
            if variable is not None:
                key = self.find_clinit_target_variable(variable)
                if key is not None:
                    if self.brute_assets(key):
                        if self.is_really_unpacked():
                            self.logger.info("fully unpacked")
                        else:
                            self.logger.info("not fully unpacked")
                        return
        else:
            self.logger.info("Cannot find zip function")
            self.logger.info("Second plan for zipper")
            r = self.second_plan()
            if r is not None:
                self.logger.info("Second plan worked")
                self.logger.info(f"{r}")
                return
            else:
                self.logger.info("Second plan failed")
                self.third_plan()
        is_default = self.default_dex_protector()
        if is_default != None:
            for key in is_default:
                self.logger.info(f"Trying default dex protector key {key}")
                if self.brute_assets(key):
                    if self.is_really_unpacked():
                        self.logger.info("fully unpacked")
                    else:
                        self.logger.info("not fully unpacked")
                    return

    def third_plan(self):
        """
        public class ldhgedudr {
            public static void fslstmkpgcrup(InputStream input, OutputStream output) throws Exception {
                InflaterInputStream is = new InflaterInputStream(input);
                InflaterOutputStream os = new InflaterOutputStream(output);
                swtj(is, os);
                os.close();
                is.close();
            }

            private static void swtj(InputStream inputStream, OutputStream outputStream) throws Exception {
                char[] key = rtpgi.kphimwvplfd.toCharArray();
        """
        input_initials = self.find_input_output_stream()
        for input_initial in input_initials:
            if input_initial is not None:
                self.logger.info("Found input output stream")
                _function, dvm = input_initial
                self.logger.info(f"{_function}")
                key = self.extract_variable_for_third_plan(_function, dvm)
                if key is not None:
                    key = utils.unescape_unicode(key)
                    self.logger.info(f"Found key : {key}")
                    if self.brute_assets(key):
                        if self.is_really_unpacked():
                            self.logger.info("fully unpacked")
                        else:
                            self.logger.info("not fully unpacked")
                        return

        return None

    def extract_variable_for_third_plan(self, target_method: EncodedMethod, dvm):
        smali_str = self.get_smali(target_method)
        """
        0059925c: 6200 9e53               0000: sget-object         v0, Lwhg/wwtgweg/mtgmdloqs/tduk/rtpgi;->kphimwvplfd:Ljava/lang/String; # field@539e
        00599260: 6e10 5099 0000          0002: invoke-virtual      {v0}, Ljava/lang/String;->toCharArray()[C # method@9950
        00599266: 0c00                    0005: move-result-object  v0
        """
        match = re.findall(
            r"sget-object [vp]\d+, (L[^;]+;->[^\(]+) Ljava/lang/String;\s+"
            r"invoke-virtual {?[vp]\d+}?, Ljava/lang/String;->toCharArray\(\)\[C",
            smali_str,
        )
        if len(match) == 0:
            self.logger.info(
                f"Unable to extract variable from {target_method.get_name()}"
            )
            self.logger.info("Exiting ...")
            return None
        if len(match) == 1:
            self.logger.info(f"Found variable ! : {match[0]}")
            key_variable = match[0].split("->")[1]
            key_class = match[0].split("->")[0]
            method = self.find_method(key_class, "<clinit>")
            if method:
                smali_str = self.get_smali(method)
                # 0059a656: 1a00 7884               0039: const-string        v0, "恐恜恞思恕恐恛恟恟恇恁恕恑思恜恊恃恃恑恕恆恛恄思恲恃恃" # string@8478
                # 0059a65a: 7120 b897 1000          003b: invoke-static       {v0, v1}, Lehl/vlnirvo/rwipgpued/dnhwp/fstmjrrront;->hfuojgtnouejrq(Ljava/lang/String;, I)Ljava/lang/String; # method@97b8
                key_variable = re.findall(
                    r"const-string [vp]\d+, \"(.*)\"\s+"
                    f"sput-object v0, {match[0]} Ljava/lang/String;",
                    smali_str,
                )
                if len(key_variable) == 1:
                    self.logger.info(
                        f"Found key variable from zip class <clinit> {key_variable[0]}"
                    )

                    return key_variable[0]
                else:
                    self.logger.info("Not found key variable from clinit")
                    self.logger.info(f"{smali_str}")
                    return None
            else:
                self.logger.info(
                    f"Not found <clinit> method for class {target_method.class_name}"
                )
                return None
        else:
            self.logger.info("Something is wrong .. 🤔")
            self.logger.info("Found multiple ?? : {match}")
            return None

    def default_dex_protector(self):
        target_class = self.find_class_in_dvms(
            "Landroid/support/dexpro/utils/DexCrypto;"
        )
        str_decrypt_keys = set()
        if target_class != None:
            self.logger.info("Found default dex protector class")
            # Find static field with name "KEY"
            for field in target_class.get_fields():
                rc4_string_variable = None
                if field.get_descriptor() != "Ljava/lang/String;":
                    continue
                if field.get_init_value() != None and field.get_init_value != "":
                    self.logger.info(
                        f"Found static key : {field.get_init_value().get_value()}"
                    )
                    static_rc4_string = field.get_init_value().get_value()
                    if static_rc4_string != None:
                        str_decrypt_keys.add(static_rc4_string)
                else:
                    if (
                        "0x0" == field.get_access_flags_string()
                        or "protected final" == field.get_access_flags_string()
                        or "" == field.get_access_flags_string()
                    ):
                        rc4_string_variable = field.get_name()

        # Find ProxyApplication
        application = self.apk_object.get_attribute_value("application", "name")
        target_method = None
        if application == None:
            # Instead find class that extends Application
            for d in self.dvms:
                for c in d.get_classes():
                    if c.get_superclassname() == "Landroid/app/Application;":
                        application = c.get_name()
                        target_method = self.find_method(application, "<init>")
                        break
        else:
            application_smali = "L" + application.replace(".", "/") + ";"
            target_method = self.find_method(application_smali, "<init>")
            self.logger.info(f"Found application class : {application} target_method : {target_method}")

        if target_method == None:
            self.logger.info("Unable to find target_method class")
            return
        smali_str = self.get_smali(target_method)

        # const-string v0, '4743504252544340435744245230474050425254'
        # invoke-static v0, Landroid/support/dexpro/utils/DexCrypto;->ab(Ljava/lang/String;)Ljava/lang/String;
        # move-result-object v0
        # iput-object v0, v1, Lxyz/magicph/dexpro/ProxyApplication;->protectKey Ljava/lang/String
        # const-string v0, "4743504252544340435744245230474050425254"
        # invoke-static v0, Landroid/support/dexpro/utils/DexCrypto;->ab(Ljava/lang/String;)Ljava/lang/String;
        # move-result-object v0
        # iput-object v0, v1, Lxyz/magicph/dexpro/ProxyApplication;->protectKey Ljava/lang/String;
        # Get const string from smali_str
        key_variable = re.findall(
            r"const-string(?:/jumbo)? [vp]\d+, \"(.*)\"\s+"
            r"invoke-static [vp]\d+, Landroid/support/dexpro/utils/DexCrypto;->[^\(]+\(Ljava/lang/String;\)Ljava/lang/String;\s+"
            r"move-result-object [vp]\d+\s+"
            r"iput-object [vp]\d+, [vp]\d+, L[^;]+;->protectKey Ljava/lang/String",
            smali_str,
        )
        r = set()
        if len(key_variable) == 1:
            self.logger.info(
                f"Found key variable from zip class <clinit> {key_variable[0]}"
            )
            x = bytes.fromhex(key_variable[0])
            for s in str_decrypt_keys:
                file_dec_key = utils.xor(x, s.encode())
                r.add(file_dec_key)

        # return set of file_Dec_key
        return r

    def second_plan(self):
        application = self.apk_object.get_attribute_value("application", "name")
        if application == None:
            return None

        application_smali = "L" + application.replace(".", "/") + ";"
        target_method = self.find_method(application_smali, "<init>")
        if target_method == None:
            return None
        smali_str = self.get_smali(target_method)
        """
        sget-object v0, Lb;->f:Ljava/lang/String;
        invoke-static {v0}, Lc;->b(Ljava/lang/String;)Ljava/lang/String;
        move-result-object v0
        """
        match = re.findall(
            r"sget-object [vp]\d+, (L[^;]+;->[^ ]+) Ljava/lang/String;\s+"
            r"invoke-static {?[vp]\d+}?, L[^;]+;->[^\(]+\(Ljava/lang/String;\)Ljava/lang/String",
            smali_str,
        )
        for matched_field in match:
            key = self.find_clinit_target_variable(matched_field)
            key = utils.unescape_unicode(key)

            if key != None:
                xor_k = 0x6033
                tmp_key = "".join(chr(xor_k ^ ord(c)) for c in key)
                self.logger.info(f"Is this a key ??? {tmp_key}")
                if tmp_key is not None:
                    if all(c in string.printable for c in tmp_key):
                        asset_list = self.apk_object.get_files()
                        for filepath in asset_list:
                            f = self.apk_object.get_file(filepath)
                            if self.solve_encryption(
                                f, tmp_key
                            ) or self.solve_encryption2(f, tmp_key):
                                return True
                    else:
                        return False

        return None

    def find_zip_function(self):
        target_method = None
        for d in self.dvms:
            for c in d.get_classes():
                for m in c.get_methods():
                    if (
                        m.get_descriptor()
                        == "(Ljava/util/zip/ZipFile; Ljava/util/zip/ZipEntry; Ljava/io/File; Ljava/lang/String;)V"
                    ):
                        self.logger.info("Found method")
                        target_method = m
                        return target_method, d
        return None

    def find_input_output_stream(self):
        target_method = None
        target_method_and_dvms = []
        for d in self.dvms:
            for c in d.get_classes():
                for m in c.get_methods():
                    if (
                        m.get_descriptor()
                        == "(Ljava/io/InputStream; Ljava/io/OutputStream;)V"
                    ):
                        if m.access_flags & 0x2 == 0x2:
                            self.logger.info("Found method with private access")

                            target_method = m
                            target_method_and_dvms.append((target_method, d))
        return target_method_and_dvms

    def find_decrypt_protect_arrays(self):
        for d in self.dvms:
            for c in d.get_classes():
                for m in c.get_methods():
                    if m.get_descriptor() == "(I)[C":
                        self.logger.info(f"Found decrypt protect arrays method {m.get_name()}")
                        smali_str = self.get_smali(m)
                        """
                        const/16 v6, 11
                        const/4 v5, 3
                        const/4 v4, 2
                        const/4 v3, 1
                        const/4 v2, 0
                        if-eqz v7, +1d6h
                        if-eq v7, v3, +1c8h
                        if-eq v7, v4, +1bdh
                        if-eq v7, v5, +005h
                        new-array v0, v2, [C
                        return-object v0
                        const/16 v0, 75
                        oto/16 -1b5
                        new-array v0, v3, [C
                        const/16 v1, 24627
                        int-to-char v1, v1
                        aput-char v1, v0, v2
                        goto/16 -1be
                        new-array v0, v4, [C
                        const/16 v1, 12293
                        aput-char v1, v0, v2
                        const/16 v1, 12294
                        aput-char v1, v0, v3
                        goto/16 -1ca
                    """
                        match = re.findall(
                            r"new-array [vp]\d+, [vp]\d+, \[C\s+"
                            r"const/16 [vp]\d+, (-?\d+)\s+"
                            r"int-to-char [vp]\d+, [vp]\d+\s+"
                            r"aput-char [vp]\d+, [vp]\d+, [vp]\d+\s+"
                            r"goto/16 -?[a-f0-9]+h\s+",
                            smali_str,
                        )
                        for m in match:
                            try:
                                xor_k = int(m)
                            except:
                                self.logger.info("bad match", m)
                                continue
                            if self.ProtectKey != None:
                                tmp_key = "".join(
                                    chr(xor_k ^ ord(c)) for c in self.ProtectKey
                                )
                                if self.brute_assets(tmp_key):
                                    self.logger.info("Decrypted from manifest")
                                    return True
                            else:
                                self.logger.info("no protect key found in manifest..")
                        else:

                            # new-array v0, v0, [C
                            # const/16 v1, 24627
                            # aput-char v1, v0, v2
                            # goto -fh
                            # Or we can extract data from fill-array-data
                            match = re.findall(
                                r"new-array [vp]\d+, [vp]\d+, \[C\s+"
                                r"const/16 [vp]\d+, (-?\d+)\s+"
                                r"aput-char [vp]\d+, [vp]\d+, [vp]\d+\s+"
                                r"goto -?[a-f0-9]+h\s+",
                                smali_str,
                            )
                            for m in match:
                                try:
                                    xor_k = int(m)
                                    print(xor_k)
                                except:
                                    self.logger.info("bad match", m)
                                    continue
                                if self.ProtectKey != None:
                                    tmp_key = "".join(
                                        chr(xor_k ^ ord(c)) for c in self.ProtectKey
                                    )
                                    if self.brute_assets(tmp_key):
                                        self.logger.info("Decrypted from manifest")
                                        return True
                                else:
                                    self.logger.info("no protect key found in manifest..")           
                            return False

    def extract_variable_from_zip(self, target_method: EncodedMethod, dvm):
        smali_str = self.get_smali(target_method)
        """
        5 invoke-virtual v3, v0, Ljava/util/zip/ZipOutputStream;->putNextEntry(Ljava/util/zip/ZipEntry;)V
        6 sget-object v0, Lcom/icecream/sandwich/c;->l Ljava/lang/String;
        7 new-instance v4, Ljava/util/zip/InflaterInputStream;
        """
        match = re.findall(
            r"invoke-virtual [vp]\d+, [vp]\d+, [vp]\d+, Ljava/util/zip/ZipEntry;->setTime\(J\)V\s+"
            r"invoke-virtual {?[vp]\d+, [vp]\d+}?, L[^;]+;->[^\(]+\(Ljava/util/zip/ZipEntry;\)V\s+"
            r"sget-object [vp]\d+, (L[^;]+;->[^\(]+) Ljava/lang/String;\s+",
            smali_str,
        )
        if len(match) == 0:
            self.logger.info(
                f"Unable to extract variable from {target_method.get_name()}"
            )
            self.logger.info("Exiting ...")
            return None
        if len(match) == 1:
            self.logger.info(f"Found variable ! : {match[0]}")
            method = self.find_method(target_method.class_name, "<clinit>")
            if method:
                smali_str = self.get_smali(method)
                key_variable = re.findall(
                    r"sget-object [vp]\d+, (L[^;]+;->[^\s]+) Ljava/lang/String;\s+"
                    f"sput-object v0, {match[0]} Ljava/lang/String;",
                    smali_str,
                )
                if len(key_variable) == 1:
                    self.logger.info(
                        f"Found key variable from zip class <clinit> {key_variable[0]}"
                    )
                    return key_variable[0]
                else:
                    self.logger.info("Not found key variable from clinit")
                    return None
        else:
            self.logger.info("Something is wrong .. 🤔")
            self.logger.info("Found multiple ?? : {match}")
            return None

    def for_fun(self, variable_string):
        variable_class, variable_field = variable_string.split("->")
        key_class = self.find_class_in_dvms(variable_class)
        if key_class == None:
            self.logger.info(f"No key class found {key_class}")
            return None

        self.logger.info(f"Key class found ! {key_class}")
        key_clinit = self.find_method(variable_class, "<clinit>")
        if key_clinit is not None:
            smali_str = self.get_smali(key_clinit)
            # self.logger.info(smali_str)
            match = re.findall(
                r"const-string [vp]\d+, \"(.*)\"\s+" rf"sput-object [vp]\d+, .*\s+",
                smali_str,
            )
            for m in match:
                xor_k = 0x6033
                tmp_key = "".join(chr(xor_k ^ ord(c)) for c in m)
                self.logger.info(f"zaa??? {tmp_key}")

    def find_clinit_target_variable(self, variable_string):
        variable_class, variable_field = variable_string.split("->")
        key_class = self.find_class_in_dvms(variable_class)
        if key_class == None:
            self.logger.info(f"No key class found {key_class}")
            return None

        self.logger.info(f"Key class found ! {key_class}")
        key_clinit = self.find_method(variable_class, "<clinit>")
        if key_clinit is not None:
            smali_str = self.get_smali(key_clinit)
            # self.logger.info(smali_str)
            match = re.findall(
                r"const-string [vp]\d+, \"(.*)\"\s+"
                rf"sput-object [vp]\d+, {variable_string} Ljava/lang/String;",
                smali_str,
            )
            if len(match) == 0:
                self.logger.info(
                    f"Cannot find string definition in clinit for target variable {variable_string}"
                )
                # If its using apkprotecttor, we can try some other method
                match = re.findall(
                    r"const-string(?:/jumbo)? [vp]\d+, \"(.*)\"\s+"
                    r"invoke-static [vp]\d+, [vp]\d+, L[^;]+;->[^\(]+\(Ljava\/lang\/String; I\)Ljava\/lang\/String;\s+"
                    r"move-result-object [vp]\d+\s+"
                    rf"sput-object [vp]\d+, {variable_string} Ljava/lang/String;",
                    smali_str,
                )
                if len(match) == 0:
                    match = re.findall(
                        r"const-string(?:/jumbo)? [vp]\d+, \"(.*)\"\s+"
                        r"invoke-static [vp]\d+, L[^;]+;->[^\(]+\(Ljava\/lang\/String;\)Ljava\/lang\/String;\s+"
                        r"move-result-object [vp]\d+\s+"
                        rf"sput-object [vp]\d+, {variable_string} Ljava/lang/String;",
                        smali_str,
                    )

                if len(match) == 1:
                    xor_k = 0x6033
                    tmp_key = "".join(chr(xor_k ^ ord(c)) for c in match[0])
                    self.logger.info(f"Is this a key ??? {tmp_key}")
                    return tmp_key
            if len(match) == 1:
                self.logger.info(f"Found key !  {match[0]}")
                return match[0]
            else:
                self.logger.info(f"Multiple key ? {match}")
        if key_clinit is None:
            self.logger.info(f"No clinit for {variable_class}")
        return None

    def brute_assets(self, key: str):
        asset_list = self.apk_object.get_files()
        for filepath in asset_list:
            f = self.apk_object.get_file(filepath)
            if self.solve_encryption(f, key) or self.solve_encryption2(f, key):
                self.logger.info("Decryption finished!!")
                return self.decrypted_payload_path
        return None

    def solve_encryption2(self, file_data, key):
        if len(file_data) < 8 or len(key) < 12:
            return False

        if file_data[0] == 0x78 and file_data[1] == 0x9C:
            try:
                encrypted = zlib.decompress(file_data)
            except Exception as e:
                self.logger.error(e)
                return False
        else:
            encrypted = file_data

        iArr = []  # 2
        iArr2 = []  # 4
        iArr3 = [None] * 27  # 27
        iArr4 = []  # 3
        if type(key) == str:
            key = [ord(x) for x in key]
        iArr = [key[8] | (key[9] << 16), key[11] << 16 | key[10]]
        iArr2.extend(
            [
                key[0] | (key[1] << 16),
                key[2] | (key[3] << 16),
                key[4] | (key[5] << 16),
                key[6] | (key[7] << 16),
            ]
        )
        iArr3[0] = iArr2[0]
        iArr4.extend([iArr2[1], iArr2[2], iArr2[3]])
        i2 = iArr2[0]
        i = 0
        while i < 26:
            i3 = i % 3
            iArr4[i3] = (
                (
                    (unsigned_rshift(ctypes.c_int32(iArr4[i3]).value, 8))
                    | ctypes.c_int32((iArr4[i3]) << 24).value
                )
                + i2
            ) ^ i
            i2 = (
                ctypes.c_int32(i2 << 3).value
                | (unsigned_rshift(ctypes.c_int32(i2).value, 29))
            ) ^ ctypes.c_int32(iArr4[i3]).value
            i += 1
            iArr3[i] = i2

        decrypted_bytes = bytearray()
        # self.logger.info(f"{iArr3}")
        z = 0
        for b in encrypted:
            if z % 8 == 0:
                h0 = iArr[0]
                h1 = iArr[1]
                for k in iArr3:
                    tmp0 = ((unsigned_rshift(h1, 8) | (h1 << 24) & 0xFFFFFFFF) + h0) ^ k
                    tmp1 = ((h0 << 3) & 0xFFFFFFFF | unsigned_rshift(h0, 29)) ^ tmp0
                    h0 = tmp1 & 0xFFFFFFFF
                    h1 = tmp0 & 0xFFFFFFFF
                iArr[0] = h0
                iArr[1] = h1
            b ^= iArr[int((z % 8) / 4)] >> (8 * (z % 4)) & 0xFF
            if (z == 0 and b != 0x78) or (z == 1 and b != 0x9C):
                return False
            z += 1
            decrypted_bytes.append(b)
        if self.check_and_write_file(decrypted_bytes):
            self.logger.info("Found in second algo finished")
            return True
        return False

    def solve_encryption(self, file_data: bytes, key: str):
        if len(file_data) < 8 or len(key) < 12:
            return False
        if file_data[0] == 0x78 and file_data[1] == 0x9C:
            try:
                encrypted = zlib.decompress(file_data)
            except Exception as e:
                self.logger.error(e)
                return False
        else:
            encrypted = file_data
        decrypted_bytes = bytearray()
        indexes = [0, 0, 0, 0, 1, 1, 1, 1]
        bits = [0, 8, 16, 24]
        if type(key) == str:
            c = [ord(x) for x in key]
        else:
            c = key
        poolArr = [(c[9] << 16) | c[8], (c[11] << 16) | c[10]]
        check_0 = (poolArr[indexes[0]]) >> bits[0] & 0xFF ^ encrypted[0]
        check_1 = (poolArr[indexes[0]]) >> bits[0] & 0xFF ^ encrypted[1]
        if check_0 != 0x78 and check_1 != 0x9C:
            return False
        for i, b in enumerate(encrypted):
            b ^= (poolArr[indexes[i % 8]]) >> bits[i % 4] & 0xFF
            decrypted_bytes.append(b)

        if self.check_and_write_file(decrypted_bytes):
            self.logger.info("Found in first algo")
            return True
        else:
            return False
