/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package esp8266;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;



import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.Register;
import ghidra.util.NumericUtilities;
import ghidra.program.flatapi.FlatProgramAPI;



/**
 * TODO: Provide class-level documentation that describes what this loader does.
 * TODO: Introducing support for SDK >= 3.0.0 FOTA SPI layout
 */
public class ESP8266Loader extends AbstractLibrarySupportLoader {

	private static final String LOAD_AS_USER1_FIRMWARE = "Load as user1.bin FOTA Image";
//	private static final String MAP_BOOTROM_IN_SPI = "Map bootrom in SPI CACHE region";
	private static final String LOAD_UNMAPPED_REGIONS = "Define unknown/unmapped memory regions";
	private static final String INIT_STACK_VALUE = "Stack register (A1) initial value";
	private static final String INIT_VECBASE_VALUE = "VECBASE registes initial value";
	
	@Override
	public String getName() {

		return "ESP8266 FOTA Image";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		
		List<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader reader = new BinaryReader(provider, true);
		try {
			new ESP8266FirmwareImage(reader, false, false);
		} catch (IOException e) {
			Msg.info(this, e);
			return loadSpecs;
		}
		
		Msg.info(this, "ESP8266 FOTA Image Matched");
		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("Xtensa:LE:32:default", "default"), true));
		return loadSpecs;

	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		boolean load_as_user1 = OptionUtils.getBooleanOptionValue(LOAD_AS_USER1_FIRMWARE, options, false);
		boolean load_unmapped_regions = OptionUtils.getBooleanOptionValue(LOAD_UNMAPPED_REGIONS, options, false);
		long init_stack_value = NumericUtilities.parseHexLong(OptionUtils.getOption(INIT_STACK_VALUE, options, NumericUtilities.toHexString(ESP8266Constants.ESP_INIT_STACK_ADDR)));
		long init_vecbase_value = NumericUtilities.parseHexLong(OptionUtils.getOption(INIT_VECBASE_VALUE, options, NumericUtilities.toHexString(ESP8266Constants.ESP_INIT_VECBASE_ADDR)));
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		AddressSpace addrspace = program.getAddressFactory().getDefaultAddressSpace();

		monitor.setMessage("ESP8266 FOTA Loader: Start loading");
		
		try {
			BinaryReader reader = new BinaryReader(provider, true);
			ESP8266FirmwareImage firmware = new ESP8266FirmwareImage(reader, load_as_user1, true);
						
			// Create ESP8622 memory regions
			createRegions(ESP8266Constants.ESP_MEMORY_REGIONS, program, monitor, log);
			
			// Create SPI FLASH CACHE regions and fill it with the firmware
			createSPIRegions(program, firmware, reader, monitor, log);
			
			// Map DRAM and IRAM from SPI CACHE
			writeUserImage(program, firmware, monitor, log);
			
			// Create unknown and protected regions
			if(load_unmapped_regions)
				createRegions(ESP8266Constants.ESP_UNMAPPED_REGIONS, program, monitor, log);
			
			// Create shadow regions
			createRegions(ESP8266Constants.ESP_SHADOW_REGIONS, program, monitor, log);
			
			// Create entry point
			Address entryAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(firmware.getMainHeader().getEntrypoint(), true);
			program.getSymbolTable().addExternalEntryPoint(entryAddress);
			
			// Set stack register
			ProgramContext context = program.getProgramContext();
			Register a1 = context.getRegister("a1"); 
			context.setValue(a1, entryAddress, entryAddress, BigInteger.valueOf(init_stack_value));
			
			// Create Exception vector namespace and fill it
			for(ESP8266Exception exception: ESP8266Constants.ESP_EXCEPTIONS)
				api.createFunction(addrspace.getAddress(ESP8266Constants.ESP_INIT_VECBASE_ADDR + exception.offset), exception.name);
			
			// Create bootrom functions
			for(ESP8266BootromFunction func: ESP8266Constants.BOOTROM_FUNCTIONS)
				api.createFunction(addrspace.getAddress(func.addr), func.name);
			
			
			// Create periphericals
			createPeripherics("DPORT0", ESP8266Constants.ESP_DPORT_REGISTERS, program, monitor);
			createPeripherics("WDEV", ESP8266Constants.ESP_WDEV_REGISTERS, program, monitor);
			createPeripherics("MMIO", ESP8266Constants.ESP_MMIO_REGISTERS, program, monitor);
			
			log.appendMsg(firmware.getDescription());
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createRegions(ESP8266MemoryRegion[] regions, Program program, TaskMonitor monitor, MessageLog log) {
		AddressSpace addrspace = program.getAddressFactory().getDefaultAddressSpace();
		Address start, shadow_base;
		boolean[] perms;
		MemoryBlock block;
		
		for (ESP8266MemoryRegion region: regions) {
			start = addrspace.getAddress(region.getRegionStart());
			perms = region.getPermissions();
			
			if(region.isRegionMapped()) {
				shadow_base = addrspace.getAddress(region.getShadowBase());
				block = MemoryBlockUtils.createByteMappedBlock(program, region.getName(), start, shadow_base, 
						(int) region.getRegionSize(), "", "", perms[0], perms[1], perms[2], false, log);
				}
			
			else
				block = MemoryBlockUtils.createUninitializedBlock(program, false, region.getName(), 
						start, region.getRegionSize(), "", "", perms[0], perms[1], perms[2], log);
			
			block.setVolatile(region.isVolatile());
		}
	}
	
	private void writeUserImage(Program program, ESP8266FirmwareImage firmware, TaskMonitor monitor, MessageLog log) throws MemoryAccessException, AddressOutOfBoundsException, LockException, NotFoundException {
		String segment_type;
		Address start;
		AddressSpace addrspace = program.getAddressFactory().getDefaultAddressSpace();
		Memory mem = program.getMemory();
		MemoryBlock block;
		
		for(AbstractESP8266Segment segment: firmware.getSegments()) {
			segment_type = segment.getType();

			// Write firmware in DRAM/IRAM
			start = addrspace.getAddress(segment.getAddress());
			block = mem.getBlock(segment_type);
			if(!block.isInitialized())
				mem.convertToInitialized(block, (byte) 0x0);
			block.putBytes(start, segment.getContent());
		}
	}
	
	private void createSPIRegions(Program program, ESP8266FirmwareImage firmware,  BinaryReader reader, TaskMonitor monitor, MessageLog log) throws IOException, MemoryAccessException, LockException, NotFoundException {
		AddressSpace addrspace = program.getAddressFactory().getDefaultAddressSpace();
		byte flash_size_raw = firmware.getFlashSizeRaw();
		ESP8266SPILayout spi_layout = ESP8266Constants.ESP8266SPILayouts[flash_size_raw];
		long base_addr = ESP8266Constants.ESP_SPI_FLASH_CACHE_BASE;
		Memory mem = program.getMemory();

		
		Address addr;
		long load_addr;
		
		MemoryBlock block;
		
		// Initialize region
		block = mem.getBlock("SPI CACHE");
		if(!block.isInitialized())
			mem.convertToInitialized(block, (byte) 0x0);
		
		// Special case SPI size 256KB
		if(firmware.getFlashSizeRaw() == 1) { // TODO: no documentation on this mode...

			// Write the whole firmware as it is
			addr = addrspace.getAddress(base_addr + ESP8266Constants.ESP_BOOTROM_SIZE);
			block.putBytes(addr, reader.readByteArray(0L, (int)reader.length()));
			return;
		}
		
		if(firmware.isUser1Firmware() || firmware.getFlashSizeRaw() > 4)
			load_addr = spi_layout.user1_bin;
		else
			load_addr = spi_layout.user2_bin;
		
		addr = addrspace.getAddress(base_addr + load_addr);
		block.putBytes(addr, reader.readByteArray(0L, (int)reader.length()));
		
	}
	
	private void createPeripherics(String name, ESP8266Peripheral peripherals[], Program program, TaskMonitor monitor) throws Exception{
		Namespace namespace = program.getSymbolTable().createNameSpace(null, name, SourceType.ANALYSIS);
		AddressSpace addrspace = program.getAddressFactory().getDefaultAddressSpace();
		SymbolTable symbtbl = program.getSymbolTable();
		Address addr;
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		
		for(ESP8266Peripheral register: peripherals) {
			addr = addrspace.getAddress(register.address);
			symbtbl.createLabel(addr, register.name, namespace, SourceType.USER_DEFINED);
			api.createDwords(addr, register.size);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		list.add(new Option(LOAD_AS_USER1_FIRMWARE, Boolean.class, false, Loader.COMMAND_LINE_ARG_PREFIX + "-user1", "ESP8266 Options"));
		list.add(new Option(LOAD_UNMAPPED_REGIONS, Boolean.class, false, Loader.COMMAND_LINE_ARG_PREFIX + "-unmapped", "ESP8266 Options"));
		list.add(new Option(INIT_STACK_VALUE, String.class, NumericUtilities.toHexString(ESP8266Constants.ESP_INIT_STACK_ADDR), Loader.COMMAND_LINE_ARG_PREFIX + "-stack", "ESP8266 Options"));
		list.add(new Option(INIT_VECBASE_VALUE, String.class, NumericUtilities.toHexString(ESP8266Constants.ESP_INIT_VECBASE_ADDR), Loader.COMMAND_LINE_ARG_PREFIX + "-vecbase", "ESP8266 Options"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		
		String name;
		Object value_raw;
		
		for (Option option : options) {
			name = option.getName();
			value_raw = option.getValue();			
			if (name.equals(INIT_STACK_VALUE)) {
				if(!validateOptionAddress((String) value_raw))
					return "Invalid stack init value";
				}
			if (name.equals(INIT_VECBASE_VALUE)) {
				if(!validateOptionAddress((String) value_raw))
					return "Invalid VECBASE init value";
				}
			
			}

		return super.validateOptions(provider, loadSpec, options, program);
	}
	
	private boolean validateOptionAddress(String value_s) {
		if(!value_s.isEmpty()) {
			try {
				long value = NumericUtilities.parseHexLong(value_s);
				if(value >= 0 && value < ESP8266Constants.ESP_LAST_ADDR)
					return true;
			} catch (NumberFormatException e) {} 
		}
		return false;
	}
}
