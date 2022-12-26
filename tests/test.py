import unittest
import os
import logging
from loguru import logger
from kavanoz.utils import InterceptHandler

logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)
# logging.getLogger().setLevel(logging.INFO)
# logging.getLogger("androguard").setLevel(logging.CRITICAL)
logger.remove()


from kavanoz.loader.multidex import LoaderMultidex
from kavanoz.loader.old_rc4 import LoaderOldRc4
from kavanoz.loader.rc4 import LoaderRc4
from kavanoz.loader.subapp import LoaderSubapp
from kavanoz.loader.moqhao import LoaderMoqhao
from kavanoz.loader.coper import LoaderCoper
from kavanoz.loader.sesdex import LoaderSesdex
from kavanoz.loader.multidex_header import LoaderMultidexHeader
from kavanoz.loader.simple_xor import LoaderSimpleXor
from kavanoz.loader.simply_xor2 import LoaderSimpleXor2
from kavanoz.loader.simple_xor_zlib import LoaderSimpleXorZlib
from kavanoz.loader.simple_aes import LoaderSimpleAes
from kavanoz.loader.appsealing import LoaderAppsealing
from kavanoz.loader.simple import LoaderSimple
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat


class TestAllLoaders(unittest.TestCase):
    def test_rc4(self):
        """
        Test that it can sum a list of integers
        """

        filename = os.path.join(
            os.path.dirname(__file__),
            "./test_apk/loader_rc4_static_key_in_key_class.apk",
        )
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderRc4(apk_object, dvms)
        res = rc4.main()
        assert res["status"] == "success"
        filename = os.path.join(
            os.path.dirname(__file__), "./test_apk/loader_rc4_second_key_0.apk"
        )
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderRc4(apk_object, dvms)
        res = rc4.main()
        assert res["status"] == "success"
        filename = os.path.join(
            os.path.dirname(__file__), "./test_apk/loader_rc4_key_0.apk"
        )
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderRc4(apk_object, dvms)
        res = rc4.main()
        res = rc4.main()
        assert res["status"] == "success"

        filename = os.path.join(
            os.path.dirname(__file__), "./test_apk/loader_rc4_multiple_stage.apk"
        )
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderRc4(apk_object, dvms)
        res = rc4.main()
        assert res["status"] == "success"

    def test_inflate(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/inflate.apk")
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderMultidex(apk_object, dvms)
        res = rc4.main()
        assert res["status"] == "success"

    def test_inflate_second(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(
            os.path.dirname(__file__),
            "./test_apk/protect_key_chines_manifest_without_zlib.apk",
        )
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderMultidex(apk_object, dvms)
        res = rc4.main()
        assert res["status"] == "success"

    def test_subapp(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/subapp.apk")
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderSubapp(apk_object, dvms)
        res = rc4.main()
        assert res["status"] == "success"

    def test_moqhao(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/moqhao.apk")
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        moqhao = LoaderMoqhao(apk_object, dvms)
        res = moqhao.main()
        assert res["status"] == "success"

    def test_coper(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/coper.apk")
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        coper = LoaderCoper(apk_object, dvms)
        res = coper.main()
        assert res["status"] == "success"

    def test_sesdex(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/sesdex.apk")
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        sesdex = LoaderSesdex(apk_object, dvms)
        res = sesdex.main()
        assert res["status"] == "success"

    def test_multidex_header(self):
        """
        Test that it can sum a list of integers
        """

        filename = os.path.join(
            os.path.dirname(__file__), "./test_apk/multidex_without_header.apk"
        )
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        mwheader = LoaderMultidexHeader(apk_object, dvms)
        res = mwheader.main()
        assert res["status"] == "success"

    def test_simple_xor(self):
        """
        Test that it can sum a list of integers
        """

        filename = os.path.join(os.path.dirname(__file__), "./test_apk/simplexor.apk")
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        sxorzlib = LoaderSimpleXor(apk_object, dvms)
        res = sxorzlib.main()
        assert res["status"] == "success"

    def test_simple_xor2(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/simple_xor2.apk")
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        sxor2 = LoaderSimpleXor2(apk_object, dvms)
        res = sxor2.main()
        assert res["status"] == "success"

    def test_simple_xor_zlib(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(
            os.path.dirname(__file__), "./test_apk/simple_xor_zlib_base64.apk"
        )
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        sxorzlib = LoaderSimpleXorZlib(apk_object, dvms)
        res = sxorzlib.main()
        assert res["status"] == "success"
        filename = os.path.join(
            os.path.dirname(__file__), "./test_apk/simple_skip4_zlib_base64.apk"
        )
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        sxorzlib = LoaderSimpleXorZlib(apk_object, dvms)
        res = sxorzlib.main()
        assert res["status"] == "success"

    def test_simple_aes(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/simpleaes.apk")
        apk_object = APK(filename)
        dvms = [DalvikVMFormat(dex) for dex in apk_object.get_all_dex()]
        saes = LoaderSimpleAes(apk_object, dvms)
        res = saes.main()
        assert res["status"] == "success"


if __name__ == "__main__":
    unittest.main()
