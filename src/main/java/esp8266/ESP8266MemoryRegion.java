package esp8266;

public class ESP8266MemoryRegion {
    private String name;
    private long start;
    private long size;
    private long shadow;
    private boolean r;
    private boolean w;
    private boolean x;
    private boolean mem_volatile;
    
    public ESP8266MemoryRegion(String name, long start, long size, long shadow, boolean r, boolean w, boolean x, boolean mem_volatile) {
        this.name = name;
        this.start = start;
        this.size = size;
        this.shadow = shadow;
        this.r = r;
        this.w = w;
        this.x = x;
        this.mem_volatile = mem_volatile;
    }
    
    public String getName() {
    	return name;
    }
    
    public long getRegionStart() {
    	return start;
    }
    
    public long getRegionSize() {
    	return size;
    }
    
    public boolean isRegionMapped() {
    	return shadow >= 0;
    }
    
    public long getShadowBase() {
    	return shadow;
    }
    
    public boolean[] getPermissions() {
    	return new boolean[] {r, w, x};
    }
    
    public boolean isVolatile() {
    	return mem_volatile;
    }
}