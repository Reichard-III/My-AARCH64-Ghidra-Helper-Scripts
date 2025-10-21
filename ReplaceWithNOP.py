#Original method was written by Packt, modified to work on AARCH64
#@author Packt
#@category Memory
#@keybinding ctrl alt shift n
#@menupath Tools.Packt.Replace with NOP
#@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;

currAddr = currentLocation.getByteAddress()
NOP = [0x1f, 0x20, 0x03, 0xd5]
instr = getInstructionAt(currAddr)
instrSize = instr.getDefaultFallThroughOffset()
removeInstructionAt(currAddr)
for i in range(instrSize):
	setByte(currAddr.addWrap(i), NOP[i])
disassemble(currAddr)
