//Writes to the BranchRegister (br) instruction address the destination addresses found in the jump table
//Select the BR instruction, have the datatypes set in the jump table, and run the script.
//Script will attempt to infer the necessary information but can fail
// - You can uncomment the "if(false)" on line 109 if you want to provide the information yourself
// - you can uncomment the "runScript("SwitchOverride.java")" on line 66 if you want it to run it right after setting references
// - I've only handled cases that I've seen myself, if you have other cases you need to handle then you'll have to do a bit of work to
//   add it in yourself. More complex cases would need you to make an entirely new script or something. 
//@author Reichard
//@category ARM
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;

public class SetJumpTableReferencesForSwitchOverride extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Function fn = getFunctionAt(currentAddress);
		Instruction i = getInstructionAt(currentAddress);
		ReferenceManager RefMgr = currentProgram.getReferenceManager();
		if(!isSwitchCase(i)) {
			//print usage
			printf("Usage: set cursor on the BR instruction the handles the jumping for the jump table make\n");
			printf("\tsure that the data in the jump table is set according to the load instructions\n");
			printf("\tThis program is not very smart and should be using Ghidra PCode to trace the relevant registers to guarantee\n");
			printf("\tproper jumpInfo collection in alternatively structured switch cases, but this is not made relevant to me yet");
			//jump info inferences can be wrong, so if you want to provide the data yourself i guess just clear the preceding
			//compare, load, and conditional branch instructions if you want to set jumpInfo variables yourself
			
			//i made it start at BR because I thought it would be more convenient to write the reference.FromAddress using the currentAddress in hindsight it would've 
			//made more sense to start at the Load and take branches until you find BR and figure out the valid values to reach the branch but that would be a lot more work
			return;
		}
		JumpInfo jumpInfo = getJumpTable(i,fn);
		if(jumpInfo==null) return;
		for(int j=0;j<jumpInfo.numJumps;j++) {
			RefMgr.addMemoryReference(i.getAddress(), jumpInfo.destinations.get(j), RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0);
			printf("%d: writing Reference from %s to %s\n",j,
					Long.toHexString(i.getAddress().getOffset()),
					Long.toHexString(jumpInfo.destinations.get(j).getOffset()));
		}
		
		runScript("SwitchOverride.java"); //uncomment this if you want it to automatically run the SwitchOverride right after setting references
	}
	
	public JumpInfo getJumpTable(Instruction i, Function fn) throws Exception {
		JumpInfo jumpInfo = new JumpInfo();
		Instruction temp = i;
		AddressSpace defaultSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
		int searchDistance = 15;
		
		if(getJumpInfo(temp, fn, jumpInfo, searchDistance)) {
			Listing listing = currentProgram.getListing();
			Address jumpTableBase = jumpInfo.jumpTableBase;
			Address lastDataAddress = jumpTableBase.add((jumpInfo.numJumps-1)*jumpInfo.mode.size);
			AddressSet addressRange = new AddressSet(jumpTableBase, lastDataAddress);
			DataIterator DataIt = listing.getData(addressRange, true);
			
			if(DataIt==null) return null;
			for(int jumpIter =0;jumpIter<jumpInfo.numJumps && DataIt.hasNext();jumpIter++) {
				Data d = DataIt.next();
				if(!checkData(jumpInfo,d,jumpIter)) continue;
				Scalar offset = null;
				
				Object obj = d.getValue();
				if(obj instanceof Scalar) 
					offset = (Scalar) obj;
				else
					throw new IllegalArgumentException("Attempted to cast object at address %s"+ jumpInfo.getHexStringDataAddress(jumpIter,d) + " to Scalar and failed");
				 
				Long Destination = jumpTableBase.getOffset()+offset.getValue();
				Address DestAddr = defaultSpace.getAddress(Destination);
				jumpInfo.destinations.add(DestAddr);
			}
			return jumpInfo;
		}
		throw new Exception(jumpInfo.getNotFoundErrors());
	}
	
	public boolean getJumpInfo(Instruction i, Function fn, JumpInfo jumpInfo, int searchLimit) throws Exception {
		//get the first jumpTableInfo you can find, as the nearest ones are likely the most relevant and I don't want them to be overwritten
		Instruction temp = i;
		ReferenceManager RefMgr = currentProgram.getReferenceManager();
		boolean deferredSetNumJumps = false;
		
		//if(false) //uncomment this line if you want to set jump info yourself without allowing script to infer anything
		while(getFunctionContaining(i.getAddress())==fn || searchLimit-- != 0) {
			temp = temp.getPrevious();
			String mnemonic = temp.getMnemonicString();
			if(mnemonic.equals("ldrsw") && !jumpInfo.jumpTableFound && jumpInfo.mode==null) {
				jumpInfo.mode = Mode.SIGNED_4BYTES;
				if(RefMgr.getReferenceDestinationCount()!=0) {
					//assuming load instruction's first reference is the correct one
					Reference[] refs = RefMgr.getReferencesFrom(temp.getAddress());
					jumpInfo.jumpTableBase = refs[0].getToAddress();
				}
				jumpInfo.jumpTableFound = true;
			} else if(mnemonic.equals("cmp") && jumpInfo.compare==null) {
				deferredSetNumJumps = true;
				jumpInfo.compare=Compare.cmp;
			} else if((mnemonic.equals("b.hi") || mnemonic.equals("b.gt")) && !jumpInfo.conditionalFound) {
				jumpInfo.conditional = Conditional.GT;
				jumpInfo.conditionalFound = true;
			} else if((mnemonic.equals("b.cs") || mnemonic.equals("b.ge")) && !jumpInfo.conditionalFound) {
				jumpInfo.conditional = Conditional.GE;
				jumpInfo.conditionalFound = true;
			}
			if(deferredSetNumJumps && jumpInfo.conditionalFound) {
				//setNumJumps requires Conditional to work so even though you'd logically read conditional before you'd read
				//the Compare it is deferred until Conditional is found to avoid setNumJumps from hitting NullPointerException
				//before getNotFoundError can report the issue
				jumpInfo.setNumJumps(temp);
				deferredSetNumJumps = false;
			}
			if(jumpInfo.conditionsMet()) return true;
		}
		//Failed to infer JumpInfo by search, allow user to specify numJumps, jumpTableBase, mode
		if(!userSetJumpInfo(jumpInfo))
			throw new Exception(jumpInfo.getNotFoundErrors());
		return true;
	}
	
	public boolean userSetJumpInfo(JumpInfo jumpInfo) throws CancelledException {
		printf("Failed to find all requisite parts of jumpTable\n");
		if(jumpInfo.numJumps==0) jumpInfo.numJumps = askInt("How many entries are there in the jump table? ", ""); 
		if(jumpInfo.jumpTableBase==null) jumpInfo.jumpTableBase = askAddress("What is the address of the jump table (not the load instruction, but the actual location of data)","");
		if(jumpInfo.mode==null) {
			List<Mode> choices = Arrays.asList(Mode.values());
			jumpInfo.mode = askChoice("Select the data reading mode that is most similar to your data type in the jump table","",choices, null);
		}
		if(jumpInfo.numJumps==0 || jumpInfo.jumpTableBase==null || jumpInfo.mode==null)
			return false;
		return true;
	}
	
	public boolean isSwitchCase(Instruction i) {
		FlowType flow = i.getFlowType();
		if(flow.isJump() && flow.isComputed())
			return true;
		printf("Instruction FlowType.isJump() = %s\tFlowType.isComputed() = %s\n",flow.isJump(),flow.isComputed());
		return false;
	}
	
	public boolean checkData(JumpInfo jumpInfo, Data d,int jumpIter) throws Exception {
		boolean correctSize,correctSign=false;
		if(d.getDataType().equals(DataType.DEFAULT)) throw new Exception("data in jumptable at "+ d.getAddress().toString() +" is not defined");
		
		correctSize = d.getLength()==jumpInfo.mode.size;
		correctSign = getSignedness(d)==jumpInfo.mode.signedness;
		if(!correctSize || !correctSign) {
			StringBuilder error = new StringBuilder();
			if(!correctSize)
				error.append("Inferred data read mode: ").append(jumpInfo.mode.toString()).append(", attempts to read data that's ").append(jumpInfo.mode.size).
					append(" bytes long and defined data in jumpTable at 0x").append(jumpInfo.getHexStringDataAddress(jumpIter,d)).append(" is ").append(d.getLength()).append("\n");
			if(!correctSign)
				error.append("Inferred data read mode: ").append(jumpInfo.mode.toString()).append(", attempts to read data that's ").append(jumpInfo.mode.signedness.toString()).
					append(" and defined data in jumpTable at 0x").append(jumpInfo.getHexStringDataAddress(jumpIter,d)).append(" is ").append(getSignedness(d).toString()).append("\n");
			throw new Exception(error.toString());
		}
		return correctSize && correctSign;
	}
	
	public Signedness getSignedness(Data d) throws Exception {
		if(d.getDataType() instanceof AbstractIntegerDataType)
			return ((AbstractIntegerDataType)d.getDataType()).isSigned() ? Signedness.signed:Signedness.unsigned;
		throw new Exception("defined data in jumpTable is not of AbstractIntegerDataType and is unhandled");
	}
	
	public class JumpInfo{
		public Mode mode;
		public Compare compare;
		public Conditional conditional;
		public long numJumps;
		public Address jumpTableBase;
		public List<Address> destinations;
		public boolean jumpTableFound = false;
		public boolean conditionalFound = false;
		
		public JumpInfo() {
			mode=null;
			compare=null;
			conditional=null;
			numJumps=0;
			jumpTableBase=null;
			destinations = new ArrayList<Address>();
		}
		
		public boolean conditionsMet() { return jumpTableFound && conditionalFound && numJumps!=0;}

		public void setNumJumps(Instruction i) throws Exception {
			//I don't know if the compiler would actually generate case switches in an alternative way but I'm leaving this here anyways
			//weird stuff like cmp + ccmp pairs are not handled and would need a bit more work to include
			//I guess it's also possible for conditional branches to operate purely by instructions that set NZCV flags, without cmp
			long cmpBounds=0; 
			switch(compare) {
			case cmp: cmpBounds = i.getScalar(1).getSignedValue(); break;
			default: throw new Exception("Compare: " + compare.toString() + " is not handled in setNumJumps");	
			}
			
			switch(conditional) {
			case GT: numJumps=cmpBounds+1; break;
			case GE: numJumps=cmpBounds; break;
			default: throw new Exception("Conditional: " +conditional.toString() + " is not handled in setNumJumps");
			}
		}

		public String getHexStringDataAddress(int index, Data d) {
			return Long.toHexString(jumpTableBase.add(d.getLength()*index).getOffset()).toString();
		}
		
		public String getNotFoundErrors() {
			StringBuilder sb = new StringBuilder();
			sb.append("Failed to find all requisite parts of jumpTable\n");
			if(numJumps==0) sb.append("\tfailed to find number of jumps, inferred by Compare (only cmp is handled) and Conditional (only b.hi/b.gt and b.cs/b.ge conditions that branch to failstates are handled)\n");
			if(!conditionalFound) sb.append("\tfailed to find conditional (only b.hi/b.gt and b.cs/b.ge conditions that branch to failstates are handled)\n");
			if(!jumpTableFound) sb.append("jumpTable not found, found by Reference destination at Load instruction (only ldrsw handled)\n");
			if(mode==null) sb.append("data read mode not found, inferred by load instruction (only ldrsw handled)\n");
			return sb.toString();
		}
	}
	
	public enum Compare{
		cmp
	}
	
	public enum Signedness{
		unsigned,
		signed
	}
	
	public enum Mode{
		SIGNED_1BYTES(1,Signedness.signed),
		UNSIGNED_1BYTES(1,Signedness.unsigned),
		SIGNED_2BYTES(2,Signedness.signed),
		UNSIGNED_2BYTES(2,Signedness.unsigned),
		SIGNED_4BYTES(4,Signedness.signed),
		UNSIGNED_4BYTES(4,Signedness.unsigned),
		SIGNED_8BYTES(8,Signedness.signed),
		UNSIGNED_8BYTES(8,Signedness.unsigned);
		
		public final int size;
		public final Signedness signedness;
		
		Mode(int i, Signedness s){
			size=i;
			signedness = s;
		}
	}
	
	public enum Conditional{
		GT, // HI, GT, 
		GE  // HS, GE
	}
}
