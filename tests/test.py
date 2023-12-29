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
from kavanoz.loader.pronlocker import LoaderPr0nLocker
from androguard.core.apk import APK
from kavanoz.loader.kangapack import LoaderKangaPack
from androguard.core.dex import DEX


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
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderRc4(apk_object, dvms, output_dir=None)
        res = rc4.main()
        assert res["status"] == "success"
        if rc4.decrypted_payload_path:
            os.remove(rc4.decrypted_payload_path)
        filename = os.path.join(
            os.path.dirname(__file__), "./test_apk/loader_rc4_second_key_0.apk"
        )
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderRc4(apk_object, dvms, output_dir=None)
        res = rc4.main()
        assert res["status"] == "success"
        if rc4.decrypted_payload_path:
            os.remove(rc4.decrypted_payload_path)
        filename = os.path.join(
            os.path.dirname(__file__), "./test_apk/loader_rc4_key_0.apk"
        )
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderRc4(apk_object, dvms, output_dir=None)
        res = rc4.main()
        assert res["status"] == "success"
        if rc4.decrypted_payload_path:
            os.remove(rc4.decrypted_payload_path)

        filename = os.path.join(
            os.path.dirname(__file__), "./test_apk/loader_rc4_multiple_stage.apk"
        )
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderRc4(apk_object, dvms, output_dir=None)
        res = rc4.main()
        assert res["status"] == "success"
        if rc4.decrypted_payload_path:
            os.remove(rc4.decrypted_payload_path)

    def test_inflate(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/inflate.apk")
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderMultidex(apk_object, dvms, output_dir=None)
        res = rc4.main()
        assert res["status"] == "success"
        if rc4.decrypted_payload_path:
            os.remove(rc4.decrypted_payload_path)

        filename = os.path.join(os.path.dirname(__file__), "./test_apk/inflate2.apk")
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderMultidex(apk_object, dvms, output_dir=None)
        res = rc4.main()
        assert res["status"] == "success"
        if rc4.decrypted_payload_path:
            os.remove(rc4.decrypted_payload_path)

        filename = os.path.join(os.path.dirname(__file__), "./test_apk/default_dex_protector.apk")
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderMultidex(apk_object, dvms, output_dir=None)
        res = rc4.main()
        assert res["status"] == "success"
        if rc4.decrypted_payload_path:
            os.remove(rc4.decrypted_payload_path)

    def test_inflate_second(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(
            os.path.dirname(__file__),
            "./test_apk/protect_key_chines_manifest_without_zlib.apk",
        )
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderMultidex(apk_object, dvms, output_dir=None)
        res = rc4.main()
        assert res["status"] == "success"
        if rc4.decrypted_payload_path:
            os.remove(rc4.decrypted_payload_path)

    def test_subapp(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/subapp.apk")
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        rc4 = LoaderSubapp(apk_object, dvms, output_dir=None)
        res = rc4.main()
        assert res["status"] == "success"
        if rc4.decrypted_payload_path:
            os.remove(rc4.decrypted_payload_path)

    def test_moqhao(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/moqhao.apk")
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        moqhao = LoaderMoqhao(apk_object, dvms, output_dir=None)
        res = moqhao.main()
        assert res["status"] == "success"
        if moqhao.decrypted_payload_path:
            os.remove(moqhao.decrypted_payload_path)

    def test_coper(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/coper.apk")
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        coper = LoaderCoper(apk_object, dvms, output_dir=None)
        res = coper.main()
        assert res["status"] == "success"
        if coper.decrypted_payload_path:
            os.remove(coper.decrypted_payload_path)

    def test_sesdex(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/sesdex.apk")
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        sesdex = LoaderSesdex(apk_object, dvms, output_dir=None)
        res = sesdex.main()
        assert res["status"] == "success"
        if sesdex.decrypted_payload_path:
            os.remove(sesdex.decrypted_payload_path)

    def test_multidex_header(self):
        """
        Test that it can sum a list of integers
        """

        filename = os.path.join(
            os.path.dirname(__file__), "./test_apk/multidex_without_header.apk"
        )
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        mwheader = LoaderMultidexHeader(apk_object, dvms, output_dir=None)
        res = mwheader.main()
        assert res["status"] == "success"
        if mwheader.decrypted_payload_path:
            os.remove(mwheader.decrypted_payload_path)

    def test_simple_xor(self):
        """
        Test that it can sum a list of integers
        """

        filename = os.path.join(os.path.dirname(__file__), "./test_apk/simplexor.apk")
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        sxorzlib = LoaderSimpleXor(apk_object, dvms, output_dir=None)
        res = sxorzlib.main()
        assert res["status"] == "success"
        if sxorzlib.decrypted_payload_path:
            os.remove(sxorzlib.decrypted_payload_path)

    def test_simple_xor2(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/simple_xor2.apk")
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        sxor2 = LoaderSimpleXor2(apk_object, dvms, output_dir=None)
        res = sxor2.main()
        assert res["status"] == "success"
        if sxor2.decrypted_payload_path:
            os.remove(sxor2.decrypted_payload_path)

    def test_simple_xor_zlib(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(
            os.path.dirname(__file__), "./test_apk/simple_xor_zlib_base64.apk"
        )
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        sxorzlib = LoaderSimpleXorZlib(apk_object, dvms, output_dir=None)
        res = sxorzlib.main()
        assert res["status"] == "success"
        if sxorzlib.decrypted_payload_path:
            os.remove(sxorzlib.decrypted_payload_path)
        filename = os.path.join(
            os.path.dirname(__file__), "./test_apk/simple_skip4_zlib_base64.apk"
        )
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        sxorzlib = LoaderSimpleXorZlib(apk_object, dvms, output_dir=None)
        res = sxorzlib.main()
        assert res["status"] == "success"
        if sxorzlib.decrypted_payload_path:
            os.remove(sxorzlib.decrypted_payload_path)

    def test_simple_aes(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/simpleaes.apk")
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        saes = LoaderSimpleAes(apk_object, dvms, output_dir=None)
        res = saes.main()
        assert res["status"] == "success"
        if saes.decrypted_payload_path:
            os.remove(saes.decrypted_payload_path)

    def test_kangapack(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/kangapack.apk")
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        skanga = LoaderKangaPack(apk_object, dvms, output_dir=None)
        res = skanga.main()
        assert res["status"] == "success"
        if skanga.decrypted_payload_path:
            os.remove(skanga.decrypted_payload_path)

    def test_pronlocker(self):
        """
        Test that it can sum a list of integers
        """
        filename = os.path.join(os.path.dirname(__file__), "./test_apk/pronlocker.apk")
        apk_object = APK(filename)
        dvms = [DEX(dex) for dex in apk_object.get_all_dex()]
        spron = LoaderPr0nLocker(apk_object, dvms, output_dir=None)
        res = spron.main()
        assert res["status"] == "success"
        if spron.decrypted_payload_path:
            os.remove(spron.decrypted_payload_path)


if __name__ == "__main__":
    unittest.main()
