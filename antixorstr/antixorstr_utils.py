import idc, idaapi, ida_ua
import ctypes

#debug info print
detail = False
def SetDebuginfo(debuginfo):
    global detail
    detail = debuginfo

def PrintDbginfo(info ="", end ='\n'):
    if detail:
        print(info, end = end)

#Trigger exception for catch in vsc use idacode: https://github.com/ioncodes/idacode
def CatchDebug():
    try:
        raise ArithmeticError
    except (ValueError, ArithmeticError):
        print("now in debug")

#get reg index from name
def GetRegConst(reg_name):
    ri = idaapi.reg_info_t()
    idaapi.parse_reg_name(ri, reg_name)
    return ri.reg

#mov rax,[rbp + reg * index + offset], function return (index, offset)
def GetOp2DisplReg(insn):
    if insn.Op2.type == idaapi.o_reg or insn.Op2.type == idaapi.o_displ or insn.Op2.type == idaapi.o_phrase:
        if insn.Op2.specflag1:
            return insn.Op2.specflag2 & 7, (insn.Op2.specflag2 >> 3) & 7
        else:
            return insn.Op2.reg, None
    else:
        return None, None

#Recommended read size for the specified offset, may not be appropriate when reuse occurs
def GetArraySize(stack_dye_ist, offset):
    for start,end in stack_dye_ist:
        if offset >= start and offset < end:
            return end - offset
    return 0

def getAlignedSize(input_size, align_size):
    fixed_size = int(input_size / align_size) * align_size
    fixed_size += align_size if input_size % align_size else 0
    return fixed_size

#return item list,ltem type eg: [sec.rva, sec.a_virtualsize, sec.a_rawsize]
def GetPefileCodesecInfo(dst_pe):
    codesec_Info = []
    for sec in dst_pe.sections:
        codesec_Info.append([sec.VirtualAddress, getAlignedSize(sec.Misc_VirtualSize, dst_pe.OPTIONAL_HEADER.SectionAlignment), getAlignedSize(sec.SizeOfRawData, dst_pe.OPTIONAL_HEADER.FileAlignment)])
    return codesec_Info

#imm dye stack space
def InsterStackOffsets(stack_dye_list, start_offset, end_offset):
    if end_offset < start_offset:
        return

    if len(stack_dye_list) == 0:
        stack_dye_list.append((start_offset, end_offset))
        return

    repair_index = -1
    for index in range(0, len(stack_dye_list)):
        obj_start, obj_end = stack_dye_list[index]
        if start_offset > obj_end:
            if index == len(stack_dye_list) - 1:
                stack_dye_list.append((start_offset, end_offset))
            continue
        if end_offset < obj_start:
            stack_dye_list.insert(index, (start_offset, end_offset))
            break
        obj_start = obj_start if obj_start < start_offset else start_offset
        obj_end = obj_end if obj_end > end_offset else end_offset
        stack_dye_list[index] = (obj_start, obj_end)
        repair_index = index
        break

    if repair_index != -1 and repair_index != len(stack_dye_list) - 1:
        remove_cnt = 0
        for index in range(repair_index + 1, len(stack_dye_list)):
            start_offset, end_offset = stack_dye_list[repair_index]
            obj_start, obj_end = stack_dye_list[index]
            if end_offset >= obj_start:
                stack_dye_list[repair_index] = (start_offset, obj_end if obj_end > end_offset else end_offset)
                remove_cnt += 1
                continue
            break

        for i in range(0, remove_cnt):
            stack_dye_list.pop(repair_index + 1)

#return insn, opname
def DecodeInsnOpname(current_ea):
    insn = ida_ua.insn_t()
    ida_ua.decode_insn(insn, current_ea)
    opname = idc.print_insn_mnem(current_ea)
    return insn, opname

#Judge whether the specified insn will modify the first parameter
def WillChangeFirst(insn):
    feature = insn.get_canon_feature()
    return True if feature & idaapi.CF_CHG1 else False

#judge whether the specific offset is in array pointers
def JudgeInOffsets(offset, pointer_offsets):
    for off, ea in pointer_offsets:
        if off == offset:
            return True
    return False

def JudgeRegNotzeroimm(imm_reg, obj_name):
    if imm_reg.get(obj_name) != None and imm_reg[obj_name] == 1:
        return True
    return False

def JudgeMemInList(obj_start, obj_end, stack_dye_list):
    for item in stack_dye_list:
        if obj_start < item[0]:
            break
        if obj_start >= item[0] and obj_end <= item[1]:
            return True
    return False

def GetStkvarOffset(insn, op_index, current_ea, sp_delta, stack_last_ea):
    if insn.ops[op_index].type != idaapi.o_displ:
        return False, 0
    if insn.ops[op_index].reg == 5:
        return True, sp_delta + idc.get_frame_regs_size(current_ea) + ctypes.c_int(insn.ops[op_index].addr).value
    elif insn.ops[op_index].reg == 4:
        return True, idc.get_frame_regs_size(current_ea) - (idc.get_spd(stack_last_ea) - idc.get_spd(current_ea)) + ctypes.c_int(insn.ops[op_index].addr).value

def FindBlockIndex(blocks, last_ea):
    for index in range(0, blocks.size):
        if last_ea >= blocks[index].start_ea:
            continue
        return index - 1
    return blocks.size - 1

#Recommend offset through cover status and start distance
def RecommendOffset(current_ea, offset, size, filter_offsets):
    recommend_offsets = []
    for pointer_offset in filter_offsets:
        if offset <= pointer_offset[0] and (offset + size) > pointer_offset[0]:
            recommend_offsets.append(pointer_offset)
    if not len(recommend_offsets):
        return False, 0
    recommend_offsets.sort(key = lambda x:abs(x[2]-current_ea))
    return True, recommend_offsets[0][0]