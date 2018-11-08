/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.elf;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Provides test cases for {@link Elf}.
 */
@RunWith(Parameterized.class)
public class ElfTest {
	private String testFile;

	public ElfTest(String testFile) {
		this.testFile = testFile;
	}

	@Parameters
	public static Collection<String> getparameters() {
		return Arrays.asList(new String[] { "ts_print", "con_flash", "helloWorld_static", "elf_64bit", "elf_arm",
				"elf_without_debug" });
	}
	// METHODS

	@Test
	public void Test() throws Exception {
		doTestReadElfObject(getResource(testFile));
	}

	private void doTestReadElfObject(File resource) throws Exception {
		Elf e = new Elf(resource);
		assertNotNull(e);

		List<SectionHeader> sections = e.sectionHeaders;
		assertNotNull(sections);

		List<ProgramHeader> programHeaders = e.programHeaders;
		assertNotNull(programHeaders);

		dumpProgramHeaders(programHeaders);

		Header header = e.header;
		assertNotNull(header);

		System.out.printf("Entry point: 0x%x\n", header.entryPoint);

		ByteBuffer buf = e.SaveToByteBuffer();

		byte[] expected = Files.readAllBytes(resource.toPath());
		byte[] actual = new byte[buf.limit()];
		buf.rewind();
		buf.get(actual);

		for (int i = 0; i < actual.length; i++) {
			assertEquals("Array differs at index " + i, expected[i], actual[i]);
		}
		assertArrayEquals(expected, actual);
	}

	/**
	 * @param aProgramHeaders
	 */
	private void dumpProgramHeaders(List<ProgramHeader> aProgramHeaders) {
		for (ProgramHeader ph : aProgramHeaders) {
			System.out.printf("Type:\t\t %s\n", ph.type);
			System.out.printf("Virtual address: 0x%x\n", ph.virtualAddress);
			System.out.printf("Physical address:0x%x\n", ph.physicalAddress);
			System.out.printf("Memory size:\t 0x%x\n", ph.segmentMemorySize);
			System.out.println();
		}
	}

	/**
	 * @param aName
	 * @return
	 * @throws URISyntaxException
	 */
	private File getResource(String aName) throws Exception {
		URL url = getClass().getClassLoader().getResource(aName);
		if ((url != null) && "file".equals(url.getProtocol())) {
			return new File(url.getPath()).getCanonicalFile();
		}
		fail("Resource " + aName + " not found!");
		return null; // to keep compiler happy...
	}

	@Test
	public void CreateElfTest() throws Exception {
		Elf readedElf = new Elf(getResource(testFile));

		Elf createdElf = new Elf(readedElf.header.elfClass, readedElf.header.elfByteOrder, readedElf.header.abiType,
				readedElf.header.elfType, readedElf.header.machineType, readedElf.header.flags, readedElf.header.entryPoint);

		for (SectionHeader section : readedElf.sectionHeaders) {
			if (section.type != SectionType.NULL) {
				createdElf.AddSection(section.section, section.getName(), section.type, section.flags, section.link,
						section.info, section.alignment, section.entrySize);
			}
		}

		for (ProgramHeader programHeader : readedElf.programHeaders) {
			createdElf.addProgramHeader(programHeader.type, programHeader.flags, programHeader.offset,
					programHeader.virtualAddress, programHeader.physicalAddress, programHeader.segmentFileSize,
					programHeader.segmentMemorySize, programHeader.segmentAlignment);
		}

		ByteBuffer byteBuffer = createdElf.SaveToByteBuffer();
		File file = new File(testFile + ".elf");
		try (FileChannel channel = new FileOutputStream(file, false).getChannel()) {
			byteBuffer.flip();
			channel.write(byteBuffer);
		}
	}

	@Test
	public void EditExistingElfFile() throws IOException, Exception {
		// Load Elf File which was Generated with objcopy from a old bin file.
		// Should contain all Necessary Code but missing Program Header to Start!
		Elf elf = new Elf(getResource("test.InternalRam.bin.elf"));
		SectionHeader sectionToLoad = elf.getSectionHeaderByType(SectionType.PROGBITS);
		elf.addProgramHeader(SegmentType.LOAD, 7, sectionToLoad.fileOffset, 0, 0, sectionToLoad.size,
				sectionToLoad.size, 0);
		
		elf.header.elfType = ObjectFileType.EXEC;
		elf.saveToFile("test.InternalRam.bin.elf.modified");
	}
}
