package esp8266;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class ESP8266Segment extends AbstractESP8266Segment {

	public ESP8266Segment(BinaryReader reader, boolean load_data) throws IOException {

		address = (int) reader.readNextUnsignedInt();
		size = (int) reader.readNextUnsignedInt();
		offset = reader.getPointerIndex();
		if(size < 0 || size > ESP8266Constants.ESP_LAST_ADDR || address < 0 || address > ESP8266Constants.ESP_LAST_ADDR)
			throw new IOException("Segment with an invalid load address.");
		
		if(load_data)
			content = reader.readNextByteArray(size);
		else
			reader.setPointerIndex(reader.getPointerIndex() + size);

	}

	public byte getChecksum() {
		byte result = (byte) 0x00;
		for (byte value: content) {
			result = (byte) (result ^ value);
		}
		return result;
	}
	
	public String getType() {
		// Rules based on ranges
		if(address >= ESP8266Constants.ESP_DRAM_START && address < ESP8266Constants.ESP_DRAM_END)
			return "DRAM";
		else if(address >= ESP8266Constants.ESP_IRAM_START && address < ESP8266Constants.ESP_IRAM_END)
			return "IRAM";
		else
			return "UNKNOWN SEGMENT";
	}
	
}
