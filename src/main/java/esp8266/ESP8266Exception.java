package esp8266;

public class ESP8266Exception {
	public long offset;
	public String name;
	
	public ESP8266Exception(long off, String n) {
		offset = off;
		name = n;
	}
}