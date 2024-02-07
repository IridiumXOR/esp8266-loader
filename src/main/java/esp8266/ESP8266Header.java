package esp8266;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class ESP8266Header implements StructConverter {
	
	private byte version;
	private byte magic;
	private byte segments;
	private byte flash_mode;
	private byte flash_size_freq;
	private long entrypoint;
	
	public ESP8266Header(BinaryReader reader) throws IOException {
		
		magic = reader.readNextByte();
		if (magic == ESP8266Constants.ESP_MAGIC_BASE) {
			version = 1;
		}
		else if(magic == ESP8266Constants.ESP_MAGIC_BASE_V2) {
			version = 2;
		}
		else {
			throw new IOException("No valid ESP8266 FOTA magic.");
		}
		
		segments = reader.readNextByte();		
		flash_mode = reader.readNextByte();		
		flash_size_freq = reader.readNextByte();		
		entrypoint = reader.readNextInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("esp8266_header", 0);
		structure.add(BYTE, 1, "magic", "Magic value");
		structure.add(BYTE, 1, "segments", "Number of segments");
		structure.add(BYTE, 1, "flash_mode", "Flash mode");
		structure.add(BYTE, 1, "flash_size_freq", "Flash size + frequency");
		structure.add(DWORD, 4, "entrypoint", "The entry function");
		return structure;
	}
		
	public byte getVersion() {
		return version;
	}
	
	public byte getMagic() {
		return magic;
	}
	

	public byte getSegmentsCount( ) {
		return segments;
	}


	public byte getFlashMode() {
		return flash_mode;
	}

	public byte getFlashSize() {
		return (byte) ((flash_size_freq & 0xF0)>> 4);
	}
	
	public byte getFlashFrequency() {
		return (byte) (flash_size_freq & 0x0F);
	}

	public long getEntrypoint() {
		return entrypoint;
	}
	
	public String getDescription() {
		String description =  String.format("\n----- ESP8266 Header -----\n" + 
											"\tMagic: 0x%X\n" +
											"\tSegments count: %d\n", magic, segments);
		String fmode;
		switch(flash_mode) {
		case 0:
			fmode = "QIO";
			break;
		case 1:
			fmode = "QOUT";
			break;
		case 2:
			fmode = "DIO";
			break;
		case 3:
			fmode = "DOUT";
			break;
		default:
			fmode = "Unknown";
		}
		description += String.format("\tFlash mode: %s\n", fmode);
		
		String f_size;
		switch(this.getFlashSize()) {
		case 0:
			f_size = "512KB (256KB + 256KB)";
			break;
		case 1:
			f_size = "256KB";
			break;
		case 2:
			f_size = "1024KB (512KB + 512KB)";
			break;
		case 3:
			f_size = "2048KB (512KB + 512KB)";
			break;
		case 4:
			f_size = "4096KB (512KB + 512KB)";
			break;
		case 5:
			f_size = "2048KB (1024KB + 1024KB)";
			break;
		case 6:
			f_size = "4096KB (1024KB + 1024KB)";
			break;
		case 7:
			f_size = "4096KB (2048KB + 2048KB)";
			break;
		case 8:
			f_size = "8192KB (1024KB + 1024KB)";
			break;
		case 9:
		    f_size = "16384KB (1024KB + 1024KB)";
		    break;
		default:
			f_size = "Unknown";
			break;
		}
		description += String.format("\tFlash size: %s\n", f_size);
		
		String f_speed;
		switch(this.getFlashFrequency()) {
		case 0:
			f_speed = "40MHz";
			break;
		case 1:
			f_speed = "26MHz";
			break;
		case 2:
			f_speed = "20MHz";
			break;
		case 15:
			f_speed = "80MHz";
			break;
		default:
			f_speed = "Unknown";
			break;
		}
		description += String.format("\tFlash speed: %s\n", f_speed);
		
		return description + String.format("\tEntrypoint: 0x%X\n", entrypoint);
	}
}
