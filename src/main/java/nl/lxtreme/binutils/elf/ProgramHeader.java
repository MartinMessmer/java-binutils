/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.elf;

import static org.junit.Assert.assertEquals;

import java.io.*;
import java.nio.*;

/**
 * Represents information about the various segments in an ELF object.
 */
public class ProgramHeader {
	public final SegmentType type;
	public final long flags;
	public long offset;
	public final long virtualAddress;
	public final long physicalAddress;
	public final long segmentFileSize;
	public final long segmentMemorySize;
	public final long segmentAlignment;

	public ProgramHeader(ElfClass elfClass, ByteBuffer buf) throws IOException {
		switch (elfClass) {
		case CLASS_32:
			type = SegmentType.valueOf(buf.getInt() & 0xFFFFFFFF);
			offset = buf.getInt() & 0xFFFFFFFFL;
			virtualAddress = buf.getInt() & 0xFFFFFFFFL;
			physicalAddress = buf.getInt() & 0xFFFFFFFFL;
			segmentFileSize = buf.getInt() & 0xFFFFFFFFL;
			segmentMemorySize = buf.getInt() & 0xFFFFFFFFL;
			flags = buf.getInt() & 0xFFFFFFFFL;
			segmentAlignment = buf.getInt() & 0xFFFFFFFFL;
			break;
		case CLASS_64:
			type = SegmentType.valueOf(buf.getInt() & 0xFFFFFFFF);
			flags = buf.getInt() & 0xFFFFFFFFL;
			offset = buf.getLong();
			virtualAddress = buf.getLong();
			physicalAddress = buf.getLong();
			segmentFileSize = buf.getLong();
			segmentMemorySize = buf.getLong();
			segmentAlignment = buf.getLong();
			break;
		default:
			throw new IOException("Unhandled ELF-class!");
		}
	}
	
	

	public ProgramHeader(SegmentType type, long flags, long offset, long virtualAddress, long physicalAddress,
			long segmentFileSize, long segmentMemorySize, long segmentAlignment) {
		this.type = type;
		this.flags = flags;
		this.offset = offset;
		this.virtualAddress = virtualAddress;
		this.physicalAddress = physicalAddress;
		this.segmentFileSize = segmentFileSize;
		this.segmentMemorySize = segmentMemorySize;
		this.segmentAlignment = segmentAlignment;
	}



	public void saveToByteBuffer(ByteBuffer buf, ElfClass elfClass) {
		switch (elfClass) {
		case CLASS_32:
			buf.limit(buf.limit() + 32);
			buf.putInt(type.ordinal());
			buf.putInt((int) offset);
			buf.putInt((int) virtualAddress);
			buf.putInt((int) physicalAddress);
			buf.putInt((int) segmentFileSize);
			buf.putInt((int) segmentMemorySize);
			buf.putInt((int) flags);
			buf.putInt((int) segmentAlignment);
			break;
		case CLASS_64:
			buf.limit(buf.limit() + 56);
			buf.putInt(type.ordinal());
			buf.putInt((int) flags);
			buf.putLong(offset);
			buf.putLong(virtualAddress);
			buf.putLong(physicalAddress);
			buf.putLong(segmentFileSize);
			buf.putLong(segmentMemorySize);
			buf.putLong(segmentAlignment);
			break;
		default:
			throw new UnsupportedOperationException("Unhandled ELF-class!");
		}
		assertEquals(buf.position(), buf.limit());
	}
}