import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.RefType;

public class FindCallsToRegistersScript extends GhidraScript {

	@Override
	public void run() throws Exception {

        Listing listing = currentProgram.getListing();
        FunctionIterator fniter = currentProgram.getFunctionManager()
            .getFunctions(true);
        int fncount = 0;
        int inscount = 0;
        int hitcount = 0;

        // Loop through all functions
        while (fniter.hasNext() && !monitor.isCancelled()) {
            Function fn = fniter.next();
            AddressSetView addrset = fn.getBody();

            // Loop through all address ranges in the function
            AddressIterator addriter = addrset.getAddresses(true);
            while (addriter.hasNext() && !monitor.isCancelled()) {
                Address addr = addriter.next();
                Instruction ins = listing.getInstructionAt(addr);

                if (ins == null) {
                    continue;
                }

                String mnemonic = ins.getMnemonicString();
                String op = ins.getDefaultOperandRepresentation(0);

                if (mnemonic.equals("CALL")) {

                    if (op.equals("RAX") || op.equals("RBX") ||
                        op.equals("RCX") || op.equals("RDX") ||
                        op.equals("RBP") || op.equals("RSP") ||
                        op.equals("RSI") || op.equals("RDI") ||
                        op.equals("R8")  || op.equals("R9")  ||
                        op.equals("R10") || op.equals("R11") ||
                        op.equals("R12") || op.equals("R13") ||
                        op.equals("R14") || op.equals("R15")) {

                        // Note the instruction
                        String insstr = fn.getName() + ", addr: " + addr + ", " +
                                        mnemonic + " " + op;
                        hitcount++;
                        println(insstr);
                        return;
                    }
                }
                inscount++;
            }
            fncount++;
        }
        String donestr = hitcount + " hits in " + inscount +
                         " instructions in "  + fncount + " functions";
        println(donestr);
	}
}
