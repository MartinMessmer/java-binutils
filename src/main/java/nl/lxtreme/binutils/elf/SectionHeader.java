/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.elf;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Represents information about the various sections in an ELF object.
 */
public class SectionHeader {
	public int nameOffset;
	private String name;

	public final SectionType type;
	public final long flags;
	public final long virtualAddress;
	public long fileOffset;
	public final long size;
	public final int link;
	public final int info;
	public final long alignment;
	public final long entrySize;
	public ByteBuffer section;

	public SectionHeader(ElfClass elfClass, ByteBuffer buf) throws IOException {
		nameOffset = buf.getInt();
		type = SectionType.valueOf(buf.getInt());

		if (elfClass == ElfClass.CLASS_32) {
			flags = buf.getInt() & 0xFFFFFFFFL;
			virtualAddress = buf.getInt() & 0xFFFFFFFFL;
			fileOffset = buf.getInt() & 0xFFFFFFFFL;
			size = buf.getInt() & 0xFFFFFFFFL;
		} else if (elfClass == ElfClass.CLASS_64) {
			flags = buf.getLong();
			virtualAddress = buf.getLong();
			fileOffset = buf.getLong();
			size = buf.getLong();
		} else {
			throw new IOException("Unhandled ELF-class!");
		}

		link = buf.getInt();
		info = buf.getInt();

		if (elfClass == ElfClass.CLASS_32) {
			alignment = buf.getInt() & 0xFFFFFFFFL;
			entrySize = buf.getInt() & 0xFFFFFFFFL;
		} else if (elfClass == ElfClass.CLASS_64) {
			alignment = buf.getLong();
			entrySize = buf.getLong();
		} else {
			throw new IOException("Unhandled ELF-class!");
		}
	}

	/**
	 * Constuctor to Create the Null Section Header
	 */
	public SectionHeader() {
		nameOffset = 0;
		type = SectionType.NULL;
		flags = 0;
		virtualAddress = 0;
		fileOffset = 0;
		size = 0;
		link = 0;
		info = 0;
		alignment = 0;
		entrySize = 0;
		section = ByteBuffer.allocate(0);
		name = "";
	}

	public SectionHeader(ByteBuffer section, String name, SectionType type, long flags, int link, int info,
			long alignment, long entrySize) {
		super();
		this.name = name;
		this.nameOffset = 0; // is Set Later from outside
		this.type = type;
		this.flags = flags;
		this.virtualAddress = 0;
		this.fileOffset = 0; // is Set Later from outside!
		this.size = section.limit();
		this.link = link;
		this.info = info;
		this.alignment = alignment;
		this.entrySize = entrySize;
		this.section = section;
	}

	public String getName() {
		return name;
	}

	void setName(String name) {
		this.name = name;
	}

	public void savteToByteBuffer(ByteBuffer buf, ElfClass elfClass) {
		switch (elfClass) {
		case CLASS_32:
			if (buf.position() == buf.limit())
				buf.limit(buf.position() + 0x28);
			buf.putInt(nameOffset);
			buf.putInt(type.ordinal());
			buf.putInt((int) flags);
			buf.putInt((int) virtualAddress);
			buf.putInt((int) fileOffset);
			buf.putInt((int) size);
			buf.putInt(link);
			buf.putInt(info);
			buf.putInt((int) alignment);
			buf.putInt((int) entrySize);
			break;
		case CLASS_64:
			if (buf.position() == buf.limit())
				buf.limit(buf.position() + 0x40);
			buf.putInt(nameOffset);
			buf.putInt(type.ordinal());
			buf.putLong(flags);
			buf.putLong(virtualAddress);
			buf.putLong(fileOffset);
			buf.putLong(size);
			buf.putInt(link);
			buf.putInt(info);
			buf.putLong(alignment);
			buf.putLong(entrySize);
			break;
		default:
			throw new UnsupportedOperationException("Unhandled ELF-class!");
		}
	}
}
