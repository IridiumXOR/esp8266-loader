package esp8266;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public abstract class AbstractESP8266Segment implements StructConverter {
	
	protected long offset;
	protected int address;
	protected int size;
	protected byte[] content = null;
	
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("esp8266_segment", 0);
		structure.add(DWORD, 1, "address", "Starting address of the segment");
		structure.add(DWORD, 1, "size", "Size of the segment");
		return structure;
	}
	
	public long getOffset() {
		return offset;
	}

	public int getAddress() {
		return address;
	}

	public int getSize() {
		return size;
	}

	public byte[] getContent() {
		return content;
	}
	
	public abstract byte getChecksum();
	public abstract String getType();
	
	public String getDescription() {
		return String.format("\n----- ESP8266 Segment -----\n" +
							 "\tOffset: 0x%X\n" +
							 "\tLoad address: 0x%X\n" +
							 "\tSize: %d\n", offset, address, size);
	}

}
