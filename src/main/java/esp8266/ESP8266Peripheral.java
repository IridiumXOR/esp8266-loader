package esp8266;

class ESP8266Peripheral {
	public long address;
	public int size;
	public String name;
	
	public ESP8266Peripheral(long addr, int s, String n) {
		address = addr;
		size = s;
		name = n;
	}
}
