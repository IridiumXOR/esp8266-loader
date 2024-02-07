package esp8266;

public class ESP8266SPILayout {
	public long bootrom;
	public long user1_bin;
	public long user1_data;
	public long user_params;
	public long reserved;
	public long user2_bin;
	public long user2_data;
	public long system_params;
	
	public ESP8266SPILayout(long bootrom, long user1_bin, long user1_data, long user_params, long reserved, long user2_bin, long user2_data, long system_params) {
		this.bootrom = bootrom;
		this.user1_bin = user1_bin;
		this.user1_data = user1_data;
		this.user_params = user_params;
		this.reserved = reserved;
		this.user2_bin = user2_bin;
		this.user2_data = user2_data;
		this.system_params = system_params;
	}
}
