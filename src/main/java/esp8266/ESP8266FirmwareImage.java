package esp8266;

import java.util.*;  
import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class ESP8266FirmwareImage {
	// TODO: il firmware versione 1 crea troppi segmenti 
	
	private byte version;
	private boolean data_loaded;
	private boolean user1_firmware;
	private long size;
	private ESP8266Header main_header;
	private ESP8266Header aux_header;
	private List<ESP8266Segment> segments = new ArrayList<ESP8266Segment>();
	private ESP8266SegmentIROM irom;
	private byte checksum = 0;

	public ESP8266FirmwareImage(BinaryReader reader, boolean user1, boolean load_data) throws IOException {
		user1_firmware = user1;
		size = reader.length();
		
		main_header = new ESP8266Header(reader);
		version = main_header.getVersion();
		
		if (version == 1) {
			
			// No auxiliary header
			aux_header = null;

			// Parse segments
			parseSegments(reader, main_header.getSegmentsCount(), load_data);
						
			// Padding
			parsePadding(reader);
			
			// Checksum
			if(load_data)
				checksum = reader.readNextByte();
			else
				reader.readNextByte();
					
			// Check second padding
			boolean valid_pad = true;
			byte a;
			while(reader.getPointerIndex() < 0x10000) {
				a = reader.readNextByte();
				if(a != (byte) 0xff) {
					valid_pad = false;
					Msg.info(this, reader.getPointerIndex());
				}
			}
			
			if(!valid_pad)
				Msg.info(this, "Anomalies in padding...");
			
			// Read IROM
			irom = new ESP8266SegmentIROM(reader, load_data, true);
	
		}
		else {
			// Read IROM
			irom = new ESP8266SegmentIROM(reader, load_data, false);
			
			// Secondary header
			aux_header = new ESP8266Header(reader);
			
			// Parse segments
			parseSegments(reader, aux_header.getSegmentsCount(), load_data);
			
			// Padding
			parsePadding(reader);
			
			// Checksum
			if(load_data)
				checksum = reader.readNextByte();
			else
				reader.readNextByte();
		}
		
		data_loaded = load_data;
	}
		

	private void parseSegments(BinaryReader reader, byte segments_count, boolean load_data) throws IOException {
		for(int i=0; i < segments_count; ++i) {
			segments.add(new ESP8266Segment(reader, load_data));
		}
	}
	
	private void parsePadding(BinaryReader reader) throws IOException {
		long index = 0;
		long length = reader.length();
		
		do {
			index = reader.getPointerIndex();
			if ((index + 1) % 16 == 0) {
				break;
			}
			reader.readNextByte();
		} while(index < length);
		
		if(index == length)
			throw new IOException("Invalid padding");
	}
	
	private byte calculateChecksum() {
		byte result = (byte) 0xef;
		for (AbstractESP8266Segment segment : segments) {
			result = (byte) (result ^ segment.getChecksum());
		}
		return result;
	}
	
	public boolean isUser1Firmware() {
		return user1_firmware;
	}
	
	public byte getVersion() {
		return version;
	}
	
	public ESP8266Header getMainHeader() {
		return main_header;
	}
	
	public ESP8266Header getAuxHeader() {
		return aux_header;
	}
	
	public List<ESP8266Segment> getSegments(){
		return segments;
	}
	
	public ESP8266SegmentIROM getIROM(){
		return irom;
	}
	
	public byte getChecksum() {
		return checksum;
	}
		
	public boolean hasValidChecksum() {
		if(data_loaded)
			return checksum == this.calculateChecksum();
		return false;
	}
	
	public long getSize() {
		return size;
	}
	
	public String getDescription() {
		String description = String.format("\n----- ESP8266 Firmware Image ----\n" +
										   "\tVersion: %d\n" +
										   "\tTotal segments count: %d\n" +
										   "\tChecksum: 0x%X\n" +
										   "\tChecksum is valid: %b\n", version, segments.size(), checksum, checksum == this.calculateChecksum());
		
		description += main_header.getDescription();
		if(aux_header != null)
			description += aux_header.getDescription();
		
		for(AbstractESP8266Segment segment: segments) {
			description += segment.getDescription();
		}
		return description;
		
	}


	public byte getFlashSizeRaw() {
		if(version == 1)
			return main_header.getFlashSize();
		return aux_header.getFlashSize();
	}
	
}