/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.elf;

import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

import nl.lxtreme.binutils.elf.DynamicEntry.Tag;

/**
 * Represents an ELF object file.
 * <p>
 * This class is <b>not</b> thread-safe!
 * </p>
 */
public class Elf implements Closeable {
	static int expectByteInRange(int in, int lowInclusive, int highInclusive, String errMsg) throws IOException {
		if (in < lowInclusive || in > highInclusive) {
			throw new IOException(errMsg);
		}
		return in;
	}

	static String getZString(byte[] buf, long offset) {
		return getZString(buf, (int) (offset & 0xFFFFFFFF));
	}

	static String getZString(byte[] buf, int offset) {
		int end = offset;
		while (end < buf.length && buf[end] != 0) {
			end++;
		}
		return new String(buf, offset, (end - offset));
	}

	static boolean isBitSet(int flags, int mask) {
		return (flags & mask) == mask;
	}

	static boolean isBitSet(long flags, long mask) {
		return (flags & mask) == mask;
	}

	static void readFully(ReadableByteChannel ch, ByteBuffer buf, String errMsg) throws IOException {
		buf.rewind();
		int read = ch.read(buf);
		if (read != buf.limit()) {
			throw new IOException(errMsg + " Read only " + read + " of " + buf.limit() + " bytes!");
		}
		buf.flip();
	}

	public final Header header;
	public final List<ProgramHeader> programHeaders;
	public final List<SectionHeader> sectionHeaders;
	public final DynamicEntry[] dynamicTable;

	// locally managed.
	private FileChannel channel;

	public Elf(File file) throws IOException {
		this(FileChannel.open(file.toPath(), StandardOpenOption.READ));
	}

	public Elf(FileChannel channel) throws IOException {
		this.channel = channel;
		this.header = new Header(channel);

		// Read the last part of the ELF header and interpret the various headers...
		ByteBuffer buf = ByteBuffer.allocate(65536);
		buf.order(header.elfByteOrder);

		// Should not be necessary unless we've not read the entire header...
		channel.position(header.programHeaderOffset);

		// Prepare for reading the program headers...
		buf.limit(header.programHeaderEntrySize);

		this.programHeaders = new ArrayList<ProgramHeader>(header.programHeaderEntryCount);
		for (int i = 0; i < header.programHeaderEntryCount; i++) {
			readFully(channel, buf, "Unable to read program header entry #" + i);

			this.programHeaders.add(new ProgramHeader(header.elfClass, buf));
		}

		// Should not be necessary unless we've not read the entire header...
		channel.position(header.sectionHeaderOffset);

		// Prepare for reading the section headers...
		buf.limit(header.sectionHeaderEntrySize);

		this.sectionHeaders = new ArrayList<SectionHeader>(header.sectionHeaderEntryCount);
		for (int i = 0; i < header.sectionHeaderEntryCount; i++) {
			readFully(channel, buf, "Unable to read section header entry #" + i);

			SectionHeader sHdr = new SectionHeader(header.elfClass, buf);
			if (i == 0) {
				// Should always be a SHT_NONE entry...
				if (sHdr.type != SectionType.NULL) {
					throw new IOException("Invalid section found! First section should always be of type SHT_NULL!");
				}
			}
			this.sectionHeaders.add(sHdr);
		}

		for (SectionHeader sectionHeader : sectionHeaders) {
			sectionHeader.section = getSection(sectionHeader);
		}

		if (header.sectionNameTableIndex != 0) {
			// There's a section name string table present...
			SectionHeader shdr = this.sectionHeaders.get(header.sectionNameTableIndex);

			buf = shdr.section;
			if (buf == null) {
				throw new IOException("Unable to get section name table!");
			}

			String stringTable = new String(buf.array(), 0, buf.limit());

			for (SectionHeader hdr : sectionHeaders) {
				int endIndex = stringTable.indexOf(0, hdr.nameOffset);
				hdr.setName(stringTable.substring(hdr.nameOffset, endIndex));
			}
		}

		ProgramHeader phdr = getProgramHeaderByType(SegmentType.DYNAMIC);
		if (phdr != null) {
			List<DynamicEntry> entries = new ArrayList<>();

			buf = getSegment(phdr);
			if (buf == null) {
				throw new IOException("Unable to get dynamic segment!");
			}

			// Walk through the entries...
			final boolean is32bit = header.is32bit();
			while (buf.remaining() > 0) {
				long tagValue = is32bit ? buf.getInt() : buf.getLong();
				long value = is32bit ? buf.getInt() : buf.getLong();
				if (tagValue == 0) {
					break;
				}
				Tag tag = Tag.valueOf((int) tagValue);

				entries.add(new DynamicEntry(tag, value));
			}

			dynamicTable = entries.toArray(new DynamicEntry[entries.size()]);
		} else {
			dynamicTable = null;
		}
	}

	public Elf(String name) throws IOException {
		this(new File(name));
	}

	/**
	 * New Constructor Added to Generate ELF and Save it later to a File!
	 */
	public Elf(ElfClass elfClass, ByteOrder byteOrder, AbiType abiType, ObjectFileType elfType, MachineType machineType,
			int flags, long entryPoint) {
		header = new Header(elfClass, byteOrder, abiType, elfType, machineType, flags, entryPoint);
		sectionHeaders = new ArrayList<SectionHeader>(1);
		sectionHeaders.add(new SectionHeader());
		programHeaders = new ArrayList<ProgramHeader>();
		dynamicTable = new DynamicEntry[0];
	}

	public void AddSection(ByteBuffer section, String name, SectionType type, long flags, int link, int info, long alignment, long entrySize) {
		SectionHeader sectionHeader = new SectionHeader(section, name, type, flags, link, info, alignment, entrySize);
		AddSection(sectionHeader);
	}

	public void AddSection(SectionHeader sectionHeader) {
		SectionHeader lastSection = sectionHeaders.get(sectionHeaders.size() - 1);
		if (lastSection.type == SectionType.NULL) {
			sectionHeader.fileOffset = header.size + header.programHeaderEntryCount * header.programHeaderEntrySize;
		} else {
			sectionHeader.fileOffset = lastSection.fileOffset + lastSection.size;
		}

		sectionHeaders.add(sectionHeader);
		header.sectionHeaderEntryCount = sectionHeaders.size();
		header.sectionHeaderOffset = sectionHeader.fileOffset + sectionHeader.size;
	}

	public void addProgramHeader(SegmentType type, long flags, long offset, long virtualAddress, long physicalAddress,
			long segmentFileSize, long segmentMemorySize, long segmentAlignment) {
		ProgramHeader programHeader = new ProgramHeader(type, flags, offset, virtualAddress, physicalAddress,
				segmentFileSize, segmentMemorySize, segmentAlignment);

		programHeaders.add(programHeader);
		header.programHeaderOffset = header.size;
		header.programHeaderEntrySize = (header.elfClass == ElfClass.CLASS_32 ? 32 : 56);
		header.programHeaderEntryCount = programHeaders.size();

		// Program Headers are inserted behind ELF Header. Sections and SectionHeaders
		// have to be moved back
		for (SectionHeader sectionHeader : sectionHeaders) {
			if (sectionHeader.type != SectionType.NULL) {
				sectionHeader.fileOffset += header.programHeaderEntrySize;
			}
		}
		header.sectionHeaderOffset += header.programHeaderEntrySize;

		// All Offsets from Program Headers Offset need also to move back
		for (ProgramHeader progHeader : programHeaders) {
			progHeader.offset += header.programHeaderEntrySize;
		}
	}

	public ByteBuffer SaveToByteBuffer() {
		saveSectionHeaderNamesToTable();
		ByteBuffer buf = ByteBuffer.allocate(0xFFFFFF);
		buf.order(header.elfByteOrder);
		header.saveToByteBuffer(buf, this);

		// Write Program Headers
		for (ProgramHeader programHeader : programHeaders) {
			programHeader.saveToByteBuffer(buf, header.elfClass);
		}

		// Write Sections
		for (SectionHeader sectionHeader : sectionHeaders) {
			buf.limit((int) (sectionHeader.fileOffset + sectionHeader.size));
			buf.position((int) sectionHeader.fileOffset);

			buf.put(sectionHeader.section);
		}

		// Write Section Headers
		if (buf.limit() < header.sectionHeaderOffset) {
			buf.limit((int) header.sectionHeaderOffset);
		}
		buf.position((int) header.sectionHeaderOffset);
		for (SectionHeader sectionHeader : sectionHeaders) {
			sectionHeader.savteToByteBuffer(buf, header.elfClass);
		}

		return buf;
	}

	private void AddString(String str, ByteBuffer buf) {
		buf.limit(buf.position() + str.length() + 1);
		buf.put(str.getBytes());
		buf.put((byte) 0);
	}

	private void saveSectionHeaderNamesToTable() {
		if (header.sectionNameTableIndex == 0) {
			ByteBuffer buf = ByteBuffer.allocate(0xFFFF);
			buf.order(header.elfByteOrder);
			for (SectionHeader sectionHeader : sectionHeaders) {
				sectionHeader.nameOffset = buf.position();
				AddString(sectionHeader.getName(), buf);
			}


			String shstrtabName = ".shstrtab";
			int shstrTabNameOffset = buf.position();
			AddString(shstrtabName, buf);
			
			buf.flip();

			SectionHeader shstrtab = new SectionHeader(buf, shstrtabName, SectionType.STRTAB, 0, 0, 0, 1, 0);
			shstrtab.nameOffset = shstrTabNameOffset;
			AddSection(shstrtab);
			header.sectionNameTableIndex = sectionHeaders.indexOf(shstrtab);
		} else {
			// TODO: add new Section Header if already exists
		}
	}

	public void saveToFile(String fileName) throws FileNotFoundException, IOException {
		try (FileOutputStream fileStream = new FileOutputStream(fileName, false)) {
			ByteBuffer buf = SaveToByteBuffer();
			buf.flip();
			fileStream.getChannel().write(buf);
		}
	}

	@Override
	public void close() throws IOException {
		if (channel != null) {
			channel.close();
			channel = null;
		}
	}

	protected StringBuilder dumpDynamicEntry(StringBuilder sb, DynamicEntry entry, byte[] stringTable) {
		sb.append(entry.getTag());
		sb.append(" => ");
		if (entry.isStringOffset()) {
			sb.append(getZString(stringTable, entry.getValue()));
		} else {
			sb.append("0x").append(Long.toHexString(entry.getValue()));
		}
		return sb;
	}

	protected StringBuilder dumpProgramHeader(StringBuilder sb, ProgramHeader phdr) {
		sb.append(phdr.type);
		sb.append(", offset: 0x").append(Long.toHexString(phdr.offset));
		sb.append(", vaddr: 0x").append(Long.toHexString(phdr.virtualAddress));
		sb.append(", paddr: 0x").append(Long.toHexString(phdr.physicalAddress));
		sb.append(", align: 0x").append(Long.toHexString(phdr.segmentAlignment));
		sb.append(", file size: 0x").append(Long.toHexString(phdr.segmentFileSize));
		sb.append(", memory size: 0x").append(Long.toHexString(phdr.segmentMemorySize));
		sb.append(", flags: ");
		if (isBitSet(phdr.flags, 0x04)) {
			sb.append("r");
		} else {
			sb.append("-");
		}
		if (isBitSet(phdr.flags, 0x02)) {
			sb.append("w");
		} else {
			sb.append("-");
		}
		if (isBitSet(phdr.flags, 0x01)) {
			sb.append("x");
		} else {
			sb.append("-");
		}
		return sb;
	}

	protected StringBuilder dumpSectionHeader(StringBuilder sb, SectionHeader shdr) {
		String name = shdr.getName();
		if (name != null) {
			sb.append(name);
		} else {
			sb.append(shdr.type);
		}
		sb.append(", size: 0x").append(Long.toHexString(shdr.size));
		sb.append(", vaddr: 0x").append(Long.toHexString(shdr.virtualAddress));
		sb.append(", foffs: 0x").append(Long.toHexString(shdr.fileOffset));
		sb.append(", align: 0x").append(Long.toHexString(shdr.alignment));
		if (shdr.link != 0) {
			sb.append(", link: 0x").append(Long.toHexString(shdr.link));
		}
		if (shdr.info != 0) {
			sb.append(", info: 0x").append(Long.toHexString(shdr.info));
		}
		if (shdr.entrySize != 0) {
			sb.append(", entrySize: 0x").append(Long.toHexString(shdr.entrySize));
		}
		return sb;
	}

	protected byte[] getDynamicStringTable() throws IOException {
		SectionHeader dynStrHdr = getSectionHeaderByType(SectionType.STRTAB);
		if (dynStrHdr == null) {
			throw new IOException("Unable to get string table for dynamic section!");
		}

		ByteBuffer dynStr = getSection(dynStrHdr);
		if (dynStr == null) {
			throw new IOException("Unable to get string table for dynamic section!");
		}

		return dynStr.array();
	}

	/**
	 * Returns the first program header with the given type.
	 * 
	 * @return the first program header with the given type, or <code>null</code> if
	 *         no such segment exists in this ELF object.
	 */
	public ProgramHeader getProgramHeaderByType(SegmentType type) {
		if (type == null) {
			throw new IllegalArgumentException("Type cannot be null!");
		}
		for (ProgramHeader hdr : programHeaders) {
			if (type.equals(hdr.type)) {
				return hdr;
			}
		}
		return null;
	}

	/**
	 * Convenience method for determining which interpreter should be used for this
	 * ELF object.
	 * 
	 * @return the name of the interpreter, or <code>null</code> if no interpreter
	 *         could be determined.
	 */
	public String getProgramInterpreter() throws IOException {
		ProgramHeader phdr = getProgramHeaderByType(SegmentType.INTERP);
		if (phdr == null) {
			return null;
		}

		ByteBuffer buf = getSegment(phdr);
		if (buf == null) {
			throw new IOException("Unable to get program interpreter segment?!");
		}

		return new String(buf.array(), 0, buf.remaining());
	}

	/**
	 * Returns the actual section data based on the information from the given
	 * header.
	 * 
	 * @return a byte buffer from which the section data can be read, never
	 *         <code>null</code>.
	 */
	private ByteBuffer getSection(SectionHeader shdr) throws IOException {
		if (shdr == null) {
			throw new IllegalArgumentException("Header cannot be null!");
		}
		if (channel == null) {
			throw new IOException("ELF file is already closed!");
		}

		ByteBuffer buf = ByteBuffer.allocate((int) shdr.size);
		buf.order(header.elfByteOrder);

		channel.position(shdr.fileOffset);
		readFully(channel, buf, "Unable to read section completely!");

		return buf;
	}

	public ByteBuffer getSectionByName(String SectionName) throws IOException {
		SectionHeader sectionHeader = sectionHeaders.stream().filter(x -> SectionName.equals(x.getName())).findFirst()
				.orElse(null);
		if (sectionHeader == null) {
			throw new IOException("Section " + SectionName + " not found");
		}
		return sectionHeader.section;
	}

	/**
	 * Returns the first section header with the given type.
	 * 
	 * @return the first section header with the given type, or <code>null</code> if
	 *         no such section exists in this ELF object.
	 */
	public SectionHeader getSectionHeaderByType(SectionType type) {
		if (type == null) {
			throw new IllegalArgumentException("Type cannot be null!");
		}
		for (SectionHeader hdr : sectionHeaders) {
			if (type.equals(hdr.type)) {
				return hdr;
			}
		}
		return null;
	}

	/**
	 * Returns the actual segment data based on the information from the given
	 * header.
	 * 
	 * @return a {@link ByteBuffer} from which the segment data can be read, never
	 *         <code>null</code>.
	 */
	public ByteBuffer getSegment(final ProgramHeader phdr) throws IOException {
		if (phdr == null) {
			throw new IllegalArgumentException("Header cannot be null!");
		}
		if (channel == null) {
			throw new IOException("ELF file is already closed!");
		}

		ByteBuffer buf = ByteBuffer.allocate((int) phdr.segmentFileSize);
		buf.order(header.elfByteOrder);

		channel.position(phdr.offset);
		readFully(channel, buf, "Unable to read segment completely!");

		return buf;
	}

	public List<String> getSharedDependencies() throws IOException {
		byte[] array = getDynamicStringTable();

		List<String> result = new ArrayList<>();
		for (DynamicEntry entry : dynamicTable) {
			if (Tag.NEEDED.equals(entry.getTag())) {
				result.add(getZString(array, (int) entry.getValue()));
			}
		}

		return result;
	}

	@Override
	public String toString() {
		try {
			StringBuilder sb = new StringBuilder();
			sb.append(header).append('\n');
			sb.append("Program header:\n");
			for (int i = 0; i < programHeaders.size(); i++) {
				sb.append('\t');
				dumpProgramHeader(sb, programHeaders.get(i));
				sb.append('\n');
			}

			byte[] strTable = getDynamicStringTable();

			sb.append("Dynamic table:\n");
			for (DynamicEntry entry : dynamicTable) {
				sb.append('\t');
				dumpDynamicEntry(sb, entry, strTable);
				sb.append('\n');
			}

			sb.append("Sections:\n");
			for (int i = 0; i < sectionHeaders.size(); i++) {
				SectionHeader shdr = sectionHeaders.get(i);
				if (!SectionType.STRTAB.equals(shdr.type)) {
					sb.append('\t');
					dumpSectionHeader(sb, sectionHeaders.get(i));
					sb.append('\n');
				}
			}
			return sb.toString();
		} catch (IOException exception) {
			throw new RuntimeException("Unable to get dynamic string table!");
		}
	}
}
