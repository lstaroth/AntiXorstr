import os
import math
import pefile
import idc, idaapi
from unicorn import *
from unicorn.x86_const import *
from antixorstr.antixorstr_utils import *

global mu
global target_32bit
global init_context
global function_basesp
global function_basespd
emu_start = 0
emu_end = 0
keypoint_ea = 0
code_hook_sleep = False
target_len = {0: 1, 1 : 2, 2 : 4, 7 : 8, 8 : 16}

def InitAntixorstrCore(map_addr, target_64bit):
    global mu
    global init_context
    global target_32bit
    if map_addr == 0:
        dst_pe = pefile.PE(idc.get_input_file_path())
        target_32bit = dst_pe.NT_HEADERS.FILE_HEADER.Machine == 0x014c
        mu = Uc(UC_ARCH_X86, UC_MODE_32 if target_32bit else UC_MODE_64)
        codesecs = GetPefileCodesecInfo(dst_pe)
        for sec in codesecs:
            mu.mem_map(dst_pe.OPTIONAL_HEADER.ImageBase + sec[0], sec[1])
            mu.mem_write(dst_pe.OPTIONAL_HEADER.ImageBase + sec[0], dst_pe.get_data(sec[0], sec[2]))
    else:
        target_32bit = not target_64bit
        mu = Uc(UC_ARCH_X86, UC_MODE_32 if target_32bit else UC_MODE_64)
        mu.mem_map(map_addr, os.path.getsize(idc.get_input_file_path()))
        mu.mem_write(map_addr, open(idc.get_input_file_path(), 'rb').read())

    CodeCallbackSleep()
    init_context = mu.context_save()
    mu.hook_add(UC_HOOK_CODE, CodeCallback)

def CodeCallbackSleep():
    global code_hook_sleep
    code_hook_sleep = True

def CodeCallbackWork():
    global code_hook_sleep
    code_hook_sleep = False

def SetEmuScope(start_ea, end_ea):
    global emu_start
    global emu_end
    emu_start = start_ea
    emu_end = end_ea

def StartEmuCode(start_ea, end_ea, limit_count = 100):
    SetEmuScope(start_ea, end_ea)
    try:
        mu.emu_start(emu_start, emu_end, count = limit_count)
    except:
        pass

def CodeCallback(mu, address, size, user_data):
    if code_hook_sleep:
        return True
    if address < emu_start or address >= emu_end:
        mu.emu_stop()
        return False
    insn, opname = DecodeInsnOpname(address)
    if "call" in opname and address > keypoint_ea:
        mu.emu_stop()
        return False
    if "push" in opname or "pop" in opname or ("call" in opname and address < keypoint_ea) or (insn.Op1.type == idaapi.o_reg and insn.Op1.reg == 4 and WillChangeFirst(insn)):
        mu.reg_write(UC_X86_REG_EIP if target_32bit else UC_X86_REG_RIP, address + size)
        return True

    mu.reg_write(UC_X86_REG_ESP if target_32bit else UC_X86_REG_RSP , function_basesp + idc.get_spd(address) - function_basespd)

def MemwriteCallback(uc, access, address, size, value, user_data):
    print(">>> Memory is being WRITE at 0x%x, data size = %u" %(address, size))

def CleanVolatileReg():
    mu.reg_write(UC_X86_REG_EAX if target_32bit else UC_X86_REG_RAX , 0)
    mu.reg_write(UC_X86_REG_ECX if target_32bit else UC_X86_REG_RCX , 0)
    mu.reg_write(UC_X86_REG_EDX if target_32bit else UC_X86_REG_RDX , 0)
    if not target_32bit:
        mu.reg_write(UC_X86_REG_R8, 0)
        mu.reg_write(UC_X86_REG_R9, 0)
        mu.reg_write(UC_X86_REG_R10, 0)
        mu.reg_write(UC_X86_REG_R11, 0)

def DecodeDecryptStr(offset, size):
    try:
        membytes = mu.mem_read(offset + 0x1000, size)
        if len(membytes.split(b'\0')[0]) == 1:
            if membytes.find(b'\x00\x00') == -1:
                return membytes.decode("utf-16")
            return membytes[:membytes.find(b'\x00\x00') + 1].decode("utf-16")
        else:
            return membytes.split(b'\0')[0].decode("utf-8")
    except:
        pass
    return ""

class Analyzer:
    def __init__(self, start, end):
        self.function_blocks = None
        self.stack_dye_list = []
        self.imm_reg = dict()
        self.real_str = []
        self.pointer_offsets = []
        self.sp_delta = 0
        self.stack_space = 0
        self.stack_last_ea = 0
        self.start_ea = start
        self.end_ea = end
        global keypoint_ea
        keypoint_ea = 0
        CodeCallbackSleep()

        mu.context_restore(init_context)
        self.Scan()

    def GetStackLastea(self):
        global function_basespd
        if target_32bit:
            base_spd = 0
            current_ea = self.start_ea
            while current_ea < self.end_ea and current_ea != idc.BADADDR:
                if idc.get_sp_delta(current_ea) > 0:
                    base_spd = idc.get_spd(current_ea)
                    break
                current_ea = idc.next_head(current_ea)
            function_basespd = base_spd
        else:
            base_spd = []
            current_ea = self.start_ea
            while current_ea < self.end_ea and current_ea != idc.BADADDR:
                current_spd = idc.get_spd(current_ea)
                if current_spd is not None and current_spd not in base_spd:
                    base_spd.append(current_spd)
                current_ea = idc.next_head(current_ea)
            base_spd.sort()
            function_basespd = base_spd[0]

        current_ea = self.start_ea
        while current_ea < self.end_ea and current_ea != idc.BADADDR:
            if idc.get_spd(current_ea) == function_basespd:
                break
            current_ea = idc.next_head(current_ea)
        self.stack_last_ea = current_ea

        #bugfix ida7.7 bug for analuze _alloca_probe spd error
        insn, _ = DecodeInsnOpname(current_ea)
        if (not target_32bit) and insn.Op1.type == idaapi.o_reg and insn.Op1.reg == 4 and WillChangeFirst(insn):
            self.stack_last_ea = idc.next_head(self.stack_last_ea)

        if self.stack_last_ea >= self.end_ea:
            return False
        return True

    def GetFunctionInfo(self):
        if not self.GetStackLastea():
            return False

        mu.mem_map(0, 0x10000)
        mu.reg_write(UC_X86_REG_ESP if target_32bit else UC_X86_REG_RSP , 0x5000)
        mu.reg_write(UC_X86_REG_EBP if target_32bit else UC_X86_REG_RBP , 0x5000)
        try:
            StartEmuCode(self.start_ea, self.stack_last_ea, 1000)
        except:
            mu.mem_unmap(0, 0x10000)
            return False

        mu.mem_unmap(0, 0x10000)
        self.stack_space = 0x5000 - mu.reg_read(UC_X86_REG_ESP if target_32bit else UC_X86_REG_RSP)
        self.sp_delta = mu.reg_read(UC_X86_REG_EBP if target_32bit else UC_X86_REG_RBP) - mu.reg_read(UC_X86_REG_ESP if target_32bit else UC_X86_REG_RSP)
        return True

    def SearchArrayPointer(self):
        current_ea = self.start_ea
        while current_ea < self.end_ea and current_ea != idc.BADADDR:
            insn, opname = DecodeInsnOpname(current_ea)
            if "lea" in opname and insn.Op2.type == idaapi.o_displ and (insn.Op2.reg == 5 or insn.Op2.reg == 4) and insn.Op1.type == idaapi.o_reg: # and (insn.Op1.reg in [1,2,8,9])
                status, offset = GetStkvarOffset(insn, 1, current_ea, self.sp_delta, self.stack_last_ea)
                if status:
                    self.pointer_offsets.append((offset, current_ea))
            current_ea = idc.next_head(current_ea)

    def DeyStackSpace(self):
        imm_reg = dict()
        current_ea = self.start_ea
        while current_ea < self.end_ea and current_ea != idc.BADADDR:
            insn, opname = DecodeInsnOpname(current_ea)
            if not WillChangeFirst(insn):
                current_ea = idc.next_head(current_ea)
                continue
            if insn.Op1.type == idaapi.o_reg:
                if insn.Op2.type == idaapi.o_phrase or insn.Op2.type == idaapi.o_displ:
                    imm_reg[insn.Op1.reg] = 0
                    if "mov" in opname and (insn.Op2.reg == 5 or insn.Op2.reg == 4):
                        status, offset = GetStkvarOffset(insn, 1, current_ea, self.sp_delta, self.stack_last_ea)
                        if status and JudgeMemInList(offset, offset + target_len[insn.Op2.dtype], self.stack_dye_list):
                            imm_reg[insn.Op1.reg] = 1
                elif insn.Op2.type == idaapi.o_reg:
                    if "xor" in opname and insn.Op1.reg == insn.Op2.reg:
                        imm_reg[insn.Op1.reg] = 0
                    elif "mov" in opname and JudgeRegNotzeroimm(imm_reg, insn.Op2.reg):
                        imm_reg[insn.Op1.reg] = 1
                elif insn.Op2.type == idaapi.o_mem or (insn.Op2.type == idaapi.o_imm and insn.Op2.value != 0):
                    if "mov" in opname:
                        imm_reg[insn.Op1.reg] = 1
                    elif imm_reg.get(insn.Op1.reg) is None:
                        imm_reg[insn.Op1.reg] = 1
            elif insn.Op1.reg == 5 or insn.Op1.reg == 4:
                if "mov" not in opname:
                    current_ea = idc.next_head(current_ea)
                    continue
                status, offset = GetStkvarOffset(insn, 0, current_ea, self.sp_delta, self.stack_last_ea)
                if status and insn.Op2.type == idaapi.o_mem or (insn.Op2.type == idaapi.o_imm and insn.Op2.value != 0):
                    InsterStackOffsets(self.stack_dye_list, offset, offset + target_len[insn.Op2.dtype])
                elif insn.Op2.type == idaapi.o_reg and JudgeRegNotzeroimm(imm_reg, insn.Op2.reg):
                    InsterStackOffsets(self.stack_dye_list, offset, offset + target_len[insn.Op2.dtype])
                elif insn.Op2.type == idaapi.o_displ and (insn.Op2.reg == 5 or insn.Op2.reg == 4):
                    status, offset = GetStkvarOffset(insn, 1, current_ea, self.sp_delta, self.stack_last_ea)
                    if status and JudgeMemInList(offset, offset + target_len[insn.Op2.dtype], self.stack_dye_list):
                        InsterStackOffsets(self.stack_dye_list, offset, offset + target_len[insn.Op2.dtype])
            current_ea = idc.next_head(current_ea)

    def SplitStackdyeList(self):
        for spliter, _ in self.pointer_offsets:
            for index in range(0, len(self.stack_dye_list)):
                if self.stack_dye_list[index][0] < spliter < self.stack_dye_list[index][1]:
                    prev_end = self.stack_dye_list[index][1]
                    self.stack_dye_list[index] = (self.stack_dye_list[index][0], spliter)
                    self.stack_dye_list.insert(index + 1, (spliter, prev_end))

    def SimulateInitdecBlock(self):
        global function_basesp
        function_basesp = idc.get_frame_regs_size(self.start_ea) + 0x1000

        CleanVolatileReg()
        mu.reg_write(UC_X86_REG_ESP if target_32bit else UC_X86_REG_RSP, idc.get_frame_regs_size(self.start_ea) + 0x1000)
        mu.reg_write(UC_X86_REG_EBP if target_32bit else UC_X86_REG_RBP, self.sp_delta + idc.get_frame_regs_size(self.start_ea) + 0x1000)

        global keypoint_ea
        first_index = FindBlockIndex(self.function_blocks, keypoint_ea)
        for index in range(first_index, self.function_blocks.size):
            block = self.function_blocks[index]
            current_ea = block.start_ea
            if block.start_ea <= keypoint_ea < block.end_ea:
                current_ea = idc.next_head(keypoint_ea)    #go on
            while current_ea < block.end_ea and current_ea != idc.BADADDR:
                keypoint_ea = current_ea
                insn, opname = DecodeInsnOpname(current_ea)
                if not WillChangeFirst(insn):
                    current_ea = idc.next_head(current_ea)
                    continue
                if insn.Op1.type == idaapi.o_reg:
                    if insn.Op2.type == idaapi.o_phrase or insn.Op2.type == idaapi.o_displ:
                        self.imm_reg[insn.Op1.reg] = 0
                        if "mov" in opname and (insn.Op2.reg == 5 or insn.Op2.reg == 4):
                            status, offset = GetStkvarOffset(insn, 1, current_ea, self.sp_delta, self.stack_last_ea)
                            if status and JudgeMemInList(offset, offset + target_len[insn.Op2.dtype], self.stack_dye_list):
                                self.imm_reg[insn.Op1.reg] = 1
                    elif insn.Op2.type == idaapi.o_reg:
                        if "xor" in opname and insn.Op1.reg == insn.Op2.reg:
                            self.imm_reg[insn.Op1.reg] = 0
                        elif "mov" in opname and JudgeRegNotzeroimm(self.imm_reg, insn.Op2.reg):
                            self.imm_reg[insn.Op1.reg] = 1
                    elif insn.Op2.type == idaapi.o_mem or (insn.Op2.type == idaapi.o_imm and insn.Op2.value != 0):
                        if "mov" in opname:
                            self.imm_reg[insn.Op1.reg] = 1
                        elif self.imm_reg.get(insn.Op1.reg) is None:
                            self.imm_reg[insn.Op1.reg] = 1
                elif insn.Op1.reg == 5 or insn.Op1.reg == 4:
                    ready_for_init = False
                    if "mov" not in opname:
                        current_ea = idc.next_head(current_ea)
                        continue
                    status, offset = GetStkvarOffset(insn, 0, current_ea, self.sp_delta, self.stack_last_ea)
                    if status and insn.Op2.type == idaapi.o_mem or (insn.Op2.type == idaapi.o_imm and insn.Op2.value != 0):
                        ready_for_init = True
                        InsterStackOffsets(self.stack_dye_list, offset, offset + target_len[insn.Op2.dtype])
                    elif insn.Op2.type == idaapi.o_reg and JudgeRegNotzeroimm(self.imm_reg, insn.Op2.reg):
                        ready_for_init = True
                        InsterStackOffsets(self.stack_dye_list, offset, offset + target_len[insn.Op2.dtype])
                    elif insn.Op2.type == idaapi.o_displ and (insn.Op2.reg == 5 or insn.Op2.reg == 4):
                        status, offset = GetStkvarOffset(insn, 1, current_ea, self.sp_delta, self.stack_last_ea)
                        if status and JudgeMemInList(offset, offset + target_len[insn.Op2.dtype], self.stack_dye_list):
                            ready_for_init = True
                            InsterStackOffsets(self.stack_dye_list, offset, offset + target_len[insn.Op2.dtype])
                    if ready_for_init:
                        status, offset = RecommendOffset(current_ea, offset, target_len[insn.Op2.dtype], self.pointer_offsets)
                        if status:
                            for reg_index in [3,7,6,12,13,14,15]:
                                self.EmuCodeWithNonvolatile(reg_index, current_ea)
                            StartEmuCode(block.start_ea if block.start_ea > self.stack_last_ea else self.stack_last_ea, self.function_blocks[self.function_blocks.size - 1].end_ea, 1000)
                            return True, offset
                current_ea = idc.next_head(current_ea)
        return False, 0

    def EmuCodeWithNonvolatile(self, reg_index, end_ea):
        block_index = FindBlockIndex(self.function_blocks, end_ea)
        preds = list(filter(lambda x:x.start_ea < self.function_blocks[block_index].start_ea, self.function_blocks[block_index].preds()))
        while True:
            if not len(preds):
                break
            current_ea = idc.prev_head(preds[0].end_ea)
            while current_ea >= preds[0].start_ea and current_ea != idc.BADADDR:
                insn, opname = DecodeInsnOpname(current_ea)
                if insn.Op1.type == idaapi.o_reg and insn.Op1.reg == reg_index and WillChangeFirst(insn) and "pop" not in opname:
                    if "lea" in opname or (insn.Op2.type != idaapi.o_phrase and insn.Op2.type != idaapi.o_displ):
                        StartEmuCode(current_ea, idc.next_head(current_ea), 1)
                        return
                current_ea = idc.prev_head(current_ea)
            preds = list(filter(lambda x:x.start_ea < preds[0].start_ea, preds[0].preds()))

    def FliterSortPointers(self):
        for index in range(0, len(self.pointer_offsets)):
            self.pointer_offsets[index] = (self.pointer_offsets[index][0], GetArraySize(self.stack_dye_list, self.pointer_offsets[index][0]), self.pointer_offsets[index][1])
        self.pointer_offsets = list(filter(lambda x: x[1] > 4, self.pointer_offsets))
        self.pointer_offsets.sort(key = lambda x:x[2])
        if len(self.pointer_offsets) == 0:
            return False

    def Scan(self):
        if (not self.GetFunctionInfo()) or self.stack_space <= 0x30:
            return False
        self.SearchArrayPointer()
        self.DeyStackSpace()
        self.FliterSortPointers()
        global keypoint_ea
        keypoint_ea = self.stack_last_ea
        mu.mem_map(0, math.ceil(self.stack_space / 0x1000) * 0x1000 + 0x2000)
        self.function_blocks = idaapi.FlowChart(None, (self.start_ea, self.end_ea))
        CodeCallbackWork()
        while True:
            try:
                status, offset = self.SimulateInitdecBlock()
            except:
                break

            if not status:
                break

            for pack in self.pointer_offsets:
                if pack[0] == offset:
                    decrypted_str = DecodeDecryptStr(offset, pack[1])
                    if len(decrypted_str) >= 3:
                        self.real_str.append(decrypted_str)
                    break

        mu.mem_unmap(0, math.ceil(self.stack_space / 0x1000) * 0x1000 + 0x2000)

def SearchFunction(start, end):
    try:
        function_analyzer = Analyzer(start, end)
        return 1, function_analyzer.real_str
    except Exception as e:
        print(f"function crash: {hex(start)}")
        print(e)
        return 1, []