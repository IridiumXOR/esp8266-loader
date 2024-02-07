package esp8266;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class ESP8266SegmentIROM extends AbstractESP8266Segment {

	public ESP8266SegmentIROM(BinaryReader reader, boolean load_data, boolean version1) throws IOException {		
		if(version1) {
			address = 0x0;
			size = (int) (reader.length() - reader.getPointerIndex());
			offset = reader.getPointerIndex();
		}
		else {
			address = (int) reader.readNextUnsignedInt();
			size = (int) reader.readNextUnsignedInt();
			offset = reader.getPointerIndex();
			if(size < 0 || size > ESP8266Constants.ESP_LAST_ADDR || address < 0 || address > ESP8266Constants.ESP_LAST_ADDR)
				throw new IOException("IROM segment with an invalid load address.");
		}
		if(load_data)
			content = reader.readNextByteArray(size);
		else
			reader.setPointerIndex(reader.getPointerIndex() + size);
	}
	
	public byte getChecksum() {
		return (byte) 0x0;
	}
	
	public String getType() {
		return "IROM";
	}
}