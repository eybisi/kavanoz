import sys
from androidemu.emulator import Emulator
from androidemu.utils.memory_helpers import read_utf8
from unicorn.unicorn_const import UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_UNMAPPED
import kavanoz.debug_utils

from unicorn import UC_HOOK_CODE
import unicorn
from unicorn.arm_const import *
import lief
from arc4 import ARC4
from kavanoz.unpack_plugin import Unpacker
import os


class LoaderCoper(Unpacker):
    def __init__(self, apk_obj, dvms, output_dir):
        super().__init__(
            "loader.coper", "Unpacker for coper", apk_obj, dvms, output_dir
        )

    def start_decrypt(self, native_lib: str = ""):
        arm32_native_libs = [
            filename
            for filename in self.apk_object.get_files()
            if filename.startswith("lib/armeabi-v7a")
        ]
        if len(arm32_native_libs) == 0:
            self.logger.info("No native lib 😔")
            return
        if len(arm32_native_libs) != 1:
            self.logger.info("Not sure this is copper but continue anyway")

        fname = arm32_native_libs[0].split("/")[-1]
        with open(fname, "wb") as fp:
            fp.write(self.apk_object.get_file(arm32_native_libs[0]))
        self.target_lib = fname
        # Show loaded modules.
        self.resolved_strings = []
        if not self.init_lib():
            return
        self.logger.info("Loaded modules:")
        if not self.setup_hook():
            self.logger.info("Failed to setup hooks maybe no srtcat symbol ?")
            self.logger.info("Trying to find strings in stack")
        # self.emulator.mu.hook_add(UC_HOOK_CODE, self.hook_debug_print)
        self.emulator.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self.hook_unmapped_read)
        try:
            self.emulator.call_symbol(self.target_module, self.target_function.name)
        except Exception as e:
            self.logger.info(f"Exception while calling symbol: {e}")
            if len(self.resolved_strings) == 0:
                self.logger.info("No strings found")
                return
        self.logger.info(f"Androidemu extracted rc4 key: {self.resolved_strings[0]}")
        self.decrypt_files(self.resolved_strings[0])
        os.remove(fname)

    def decrypt_files(self, rc4key: str):
        for filepath in self.apk_object.get_files():
            fd = self.apk_object.get_file(filepath)
            dede = ARC4(rc4key)
            dec = dede.decrypt(fd)
            if self.check_and_write_file(dec):
                return True
        return False

    def init_lib(self):
        target_ELF = lief.ELF.parse(self.target_lib)
        java_exports = [
            jf for jf in target_ELF.exported_functions if jf.name.startswith("Java_")
        ]
        if len(java_exports) == 0:
            return False
        if len(java_exports) > 1:
            self.logger.info("Not sure this is copper but continue anyway")

        self.target_function = java_exports[0]
        # Configure logging

        # Initialize emulator
        self.emulator = Emulator(vfp_inst_set=True)
        libc_path = os.path.join(os.path.dirname(__file__), "androidnativeemu/libc.so")
        self.emulator.load_library(libc_path, do_init=False)
        self.target_module = self.emulator.load_library(self.target_lib, do_init=False)
        return True

    def hook_debug_print(self, uc, address, size, user_data):
        instruction = uc.mem_read(address, size)
        instruction_str = "".join("{:02x} ".format(x) for x in instruction)

        print(
            "# Tracing instruction at 0x%x, instruction size = 0x%x, instruction = %s"
            % (address, size, instruction_str)
        )

    def hook_unmapped_read(self, uc, access, address, size, value, user_data):
        # Read stack and print it byte per byte
        sp = uc.reg_read(UC_ARM_REG_SP)
        print(f"\nStack pointer: {hex(sp)}")
        stack_data = uc.mem_read(sp, 0x400)
        # Stack data contains list of strings ends with \x00 but there are also
        # filler \x00 bytes in between them. We need to split them.
        stack_data = stack_data.split(b"\x00")
        # Filter out empty strings
        stack_data = [x for x in stack_data if x != b""]
        # Decode strings
        stack_data = [x for x in stack_data]
        print(f"Stack data: {stack_data}")
        self.resolved_strings.append(stack_data[-1].decode("utf-8"))
        # Print stack

    def setup_hook(self):
        for module in self.emulator.modules:
            if module.filename == self.target_lib:
                self.logger.info("[0x%x] %s" % (module.base, module.filename))
                # emulator.mu.hook_add(
                # UC_HOOK_CODE,
                # hook_code,
                # begin=module.base + java_func_obj.address,
                # end=module.base + java_func_obj.address + (0x2198 - 0x1FC1),
                # )
                strncat = module.find_symbol("__strncat_chk")
                if strncat == None:
                    self.logger.info("No strncat symbol 😔")
                    return False
                self.logger.debug(f"{hex(strncat.address)} strcat_chk addr")
                self.emulator.mu.hook_add(
                    UC_HOOK_CODE,
                    self.hook_strncat,
                    begin=strncat.address,
                    end=strncat.address + 1,
                )
                self.emulator.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.hook_mem_read)
                self.emulator.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self.hook_mem_read)
                return True

    def hook_mem_read(self, uc, access, address, size, value, user_data):
        pc = uc.reg_read(UC_ARM_REG_PC)
        data = uc.mem_read(address, size)
        self.logger.debug(
            ">>> Memory READ at 0x%x, data size = %u, pc: %x, data value = 0x%s"
            % (address, size, pc, data.hex())
        )

    def hook_strncat(self, uc: unicorn.unicorn.Uc, address, size, user_data):
        # print(f"current strncat hook addr : {hex(address)}")
        r0 = uc.reg_read(UC_ARM_REG_R0)
        # print(f"current strncat hook r0 : {hex(r0)}")
        r1 = uc.reg_read(UC_ARM_REG_R1)
        max_size = uc.reg_read(UC_ARM_REG_R2)
        # print(f"current strncat hook r1 : {hex(r1)}")
        cur_key = read_utf8(uc, r0)
        added = read_utf8(uc, r1)
        final_str = cur_key + added
        if len(final_str) == max_size - 1:
            self.logger.debug(f"current strncat hook final_str : {final_str}")
            self.resolved_strings.append(final_str)
            if len(self.resolved_strings) > 10:
                self.emulator.mu.emu_stop()

    # def hook_code(self,uc: unicorn.unicorn.Uc, address, size, user_data):
    # global rc4_key
    # if address == coper_base + java_func_obj.address + (0x2198 - 0x1FC1):
    # sp = uc.reg_read(UC_ARM_REG_SP)
    # rc4_key = read_utf8(uc, sp + 0x46F)

    # print(
    # "# Tracing instruction at 0x%x, instruction size = 0x%x, instruction = %s"
    # % (address, size, instruction_str)
    # )
    # if instruction[0] == 0xA0 and instruction[1] == 0x47 and len(instruction) == 2:
    # r1 = uc.reg_read(UC_ARM_REG_R1)
    # print(r1)
    # print(uc.mem_read(r1, 1))
