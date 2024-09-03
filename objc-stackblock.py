from typing import Optional, List

import idautils
import ida_idp
import ida_ua
import ida_funcs
import ida_typeinf
import ida_frame
import ida_name
import idaapi

STACK_BLOCK_NAME = "__NSConcreteStackBlock_ptr"


def findStackBlock() -> Optional[tuple[int, str]]:
    for ea, name in idautils.Names():
        if name == STACK_BLOCK_NAME:
            return ea, name
    return None


def getSrcOps(instruction: ida_ua.insn_t) -> List[ida_ua.op_t]:
    srcFlags = [
        ida_idp.CF_USE1,
        ida_idp.CF_USE2,
        ida_idp.CF_USE3,
        ida_idp.CF_USE4,
        ida_idp.CF_USE5,
        ida_idp.CF_USE6,
        ida_idp.CF_USE7,
        ida_idp.CF_USE8,
    ]

    srcOps = []

    instructionFeature = instruction.get_canon_feature()
    for index, flag in enumerate(srcFlags):
        if instructionFeature & flag != 0:
            srcOps.append(instruction.ops[index])

    return srcOps


def getDstOp(instruction: ida_ua.insn_t) -> Optional[ida_ua.op_t]:
    srcFlags = [
        ida_idp.CF_CHG1,
        ida_idp.CF_CHG2,
        ida_idp.CF_CHG3,
        ida_idp.CF_CHG4,
        ida_idp.CF_CHG5,
        ida_idp.CF_CHG6,
        ida_idp.CF_CHG7,
        ida_idp.CF_CHG8,
    ]

    instructionFeature = instruction.get_canon_feature()
    for index, flag in enumerate(srcFlags):
        if instructionFeature & flag != 0:
            return instruction.ops[index]

    return None


def extractStackBlockInvoke(
    xrefList: ida_frame.xreflist_t, upperDecodingBoundary: int
) -> Optional[ida_funcs.func_t]:
    xref: ida_frame.xreflist_entry_t
    for xref in xrefList:
        instruction = idautils.DecodeInstruction(xref.ea)

        # checking if xref stores into the NS stack block
        dstOp = getDstOp(instruction)
        if dstOp is None or dstOp.n != xref.opnum:
            continue

        srcRegisters = list(map(lambda op: op.reg, getSrcOps(instruction)))
        if len(srcRegisters) == 0:
            continue

        currentEa = xref.ea

        while currentEa > upperDecodingBoundary:
            instruction = idautils.DecodePreviousInstruction(currentEa)
            currentEa = instruction.ea

            # trying to find an instruction that stores something into one of the src registers
            dstOp = getDstOp(instruction)
            if dstOp is None or dstOp.reg not in srcRegisters:
                continue

            srcRegisters.remove(dstOp.reg)

            dataRefs = idautils.DataRefsFrom(instruction.ea)
            possibleFunctions = map(lambda ref: ida_funcs.get_func(ref), dataRefs)
            funcs: List[ida_funcs.func_t] = [
                func for func in possibleFunctions if func is not None
            ]

            if len(funcs) != 0:
                return funcs[0]


def isUserNamed(func: ida_funcs.func_t, functionName: str) -> bool:
    if functionName.startswith("sub_"):
        hexAddr = "{:X}".format(func.start_ea)
        if functionName.split("sub_")[1] == hexAddr:
            return False

    return True


def processDataRef(dataRef: int):
    currentFunc: ida_funcs.func_t = ida_funcs.get_func(dataRef)
    if currentFunc is None:
        idaapi.msg(
            "ObjC-StackBlock: failed to find function for {:x}, skipping...\n".format(
                dataRef
            )
        )
        return

    funcName = ida_funcs.get_func_name(dataRef)

    stackFrame = ida_typeinf.tinfo_t()
    if not stackFrame.get_func_frame(currentFunc):
        idaapi.msg(
            "ObjC-StackBlock: failed to get stack frame for {}, skipping...\n".format(
                funcName
            )
        )
        return

    stackFrameUdt = ida_typeinf.udt_type_data_t()
    if not stackFrame.get_udt_details(stackFrameUdt):
        idaapi.msg(
            "ObjC-StackBlock: failed to get stack frame udt for {}, skipping...\n".format(
                funcName
            )
        )
        return

    ptrLoadIns = idautils.DecodeInstruction(dataRef)
    stackBlockOp = getDstOp(ptrLoadIns)
    if stackBlockOp is None:
        idaapi.msg(
            "ObjC-StackBlock: failed to find stack block operand for {}:{:X}, skipping...\n".format(
                funcName, dataRef
            )
        )
        return

    dataRef += ptrLoadIns.size

    stackBlockStoreIns = None
    while stackBlockStoreIns is None and dataRef < currentFunc.end_ea:
        instruction = idautils.DecodeInstruction(dataRef)
        dataRef += instruction.size

        srcOps = getSrcOps(instruction)
        matchingOp = next((op for op in srcOps if op.reg == stackBlockOp.reg), None)
        if matchingOp is None:
            continue

        stackBlockStoreIns = instruction
        break

    if stackBlockStoreIns is None:
        idaapi.msg(
            "ObjC-StackBlock: failed to find stack block destination for {}, skipping...\n",
            funcName,
        )
        return

    dataRef += stackBlockStoreIns.size

    stackBlockDst = getDstOp(stackBlockStoreIns)
    if stackBlockDst is None:
        idaapi.msg(
            "ObjC-StackBlock: failed to get dst operand for {}:{:X}, skipping...\n".format(
                funcName, stackBlockStoreIns.ea
            )
        )
        return

    stackFrameNSBlockIndex = stackFrame.get_stkvar(
        stackBlockStoreIns, stackBlockDst, stackBlockDst.addr
    )

    if stackFrameNSBlockIndex == -1:
        idaapi.msg(
            "ObjC-StackBlock: failed to get stack frame NSBlock index for {}:{:X}, skipping...\n".format(
                funcName, stackBlockStoreIns.ea
            )
        )
        return

    nsBlockUdm = stackFrameUdt[stackFrameNSBlockIndex]
    nsOffsetBytes = int(nsBlockUdm.offset / 8)
    nsSizeBytes = int(nsBlockUdm.size / 8)

    xrefList = ida_frame.xreflist_t()
    ida_frame.build_stkvar_xrefs(
        xrefList, currentFunc, nsOffsetBytes, nsOffsetBytes + nsSizeBytes
    )

    invokeFunction = extractStackBlockInvoke(xrefList, dataRef)

    if invokeFunction is None:
        return

    invokeName = ida_funcs.get_func_name(invokeFunction.start_ea)

    if not isUserNamed(invokeFunction, invokeName):
        dstName = "calledFrom_{}".format(funcName)
        idaapi.msg("ObjC-StackBlock: renaming {} to {}\n".format(invokeName, dstName))
        ida_name.set_name(invokeFunction.start_ea, dstName, ida_name.SN_FORCE)


def run():
    stackBlock = findStackBlock()

    if stackBlock is None:
        idaapi.msg("ObjC-StackBlock: failed to find {}\n".format(STACK_BLOCK_NAME))
        return

    blockEa, blockName = stackBlock
    dataRefs = idautils.DataRefsTo(blockEa)

    for ref in dataRefs:
        processDataRef(ref)


run()
