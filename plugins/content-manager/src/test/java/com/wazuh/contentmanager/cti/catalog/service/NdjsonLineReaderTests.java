/*
 * Copyright (C) 2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.contentmanager.cti.catalog.service;

import org.opensearch.test.OpenSearchTestCase;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Unit tests for {@link NdjsonLineReader}: it must split a stream exactly as {@link
 * BufferedReader#readLine()} did before the snapshot path moved to bytes, whatever the buffer size,
 * and it must not keep an outsized buffer once the long line is consumed.
 */
public class NdjsonLineReaderTests extends OpenSearchTestCase {

    /** Reads every line with a {@link NdjsonLineReader}, decoding each one as UTF-8. */
    private static List<String> readAll(byte[] data, int initialCapacity, int maxRetained)
            throws IOException {
        NdjsonLineReader reader =
                new NdjsonLineReader(new ByteArrayInputStream(data), initialCapacity, maxRetained);
        List<String> lines = new ArrayList<>();
        while (reader.next()) {
            lines.add(
                    new String(
                            reader.buffer(), reader.lineStart(), reader.lineLength(), StandardCharsets.UTF_8));
        }
        return lines;
    }

    /** The reference: the lines {@link BufferedReader#readLine()} returns for the same bytes. */
    private static List<String> readAllWithBufferedReader(byte[] data) throws IOException {
        BufferedReader reader =
                new BufferedReader(
                        new InputStreamReader(new ByteArrayInputStream(data), StandardCharsets.UTF_8));
        List<String> lines = new ArrayList<>();
        String line;
        while ((line = reader.readLine()) != null) {
            lines.add(line);
        }
        return lines;
    }

    private static void assertSameLinesAsBufferedReader(String content) throws IOException {
        byte[] data = content.getBytes(StandardCharsets.UTF_8);
        List<String> expected = readAllWithBufferedReader(data);
        // A 4-byte buffer forces refills and growth in the middle of lines and of terminators.
        for (int capacity : new int[] {4, 7, 64, 64 * 1024}) {
            assertEquals("capacity " + capacity, expected, readAll(data, capacity, capacity * 2));
        }
    }

    public void testSplitsOnNewlines() throws IOException {
        assertSameLinesAsBufferedReader("{\"a\":1}\n{\"b\":2}\n{\"c\":3}");
    }

    public void testTrailingNewlineDoesNotAddAnEmptyLine() throws IOException {
        assertSameLinesAsBufferedReader("{\"a\":1}\n{\"b\":2}\n");
    }

    public void testKeepsEmptyLines() throws IOException {
        assertSameLinesAsBufferedReader("{\"a\":1}\n\n\n{\"b\":2}");
    }

    public void testCarriageReturnTerminators() throws IOException {
        assertSameLinesAsBufferedReader("{\"a\":1}\r\n{\"b\":2}\r{\"c\":3}\r\n\r\n{\"d\":4}\r");
    }

    public void testEmptyStream() throws IOException {
        assertSameLinesAsBufferedReader("");
    }

    public void testMultibyteCharactersStayIntact() throws IOException {
        assertSameLinesAsBufferedReader("{\"t\":\"café ’quoted’ 漢字 😀\"}\n{\"t\":\"ñ\"}");
    }

    /** A line longer than the buffer grows it; it is then returned whole. */
    public void testLineLongerThanTheBuffer() throws IOException {
        String longLine = "{\"x\":\"" + "y".repeat(100_000) + "\"}";
        String content = "{\"a\":1}\n" + longLine + "\n{\"b\":2}";
        assertSameLinesAsBufferedReader(content);
    }

    /**
     * Once an outsized line is consumed the buffer goes back to its initial size, so it does not stay
     * pinned for the rest of the load.
     */
    public void testReleasesTheBufferAfterAnOutsizedLine() throws IOException {
        String longLine = "{\"x\":\"" + "y".repeat(10_000) + "\"}";
        byte[] data =
                ("{\"a\":1}\n" + longLine + "\n{\"b\":2}\n{\"c\":3}").getBytes(StandardCharsets.UTF_8);
        NdjsonLineReader reader = new NdjsonLineReader(new ByteArrayInputStream(data), 64, 256);

        assertTrue(reader.next());
        assertTrue(reader.next());
        assertEquals(longLine.length(), reader.lineLength());
        assertTrue("the long line needs a bigger buffer", reader.capacity() > 256);

        assertTrue(reader.next());
        assertEquals(64, reader.capacity());
        assertEquals(
                "{\"b\":2}",
                new String(
                        reader.buffer(), reader.lineStart(), reader.lineLength(), StandardCharsets.UTF_8));
        assertTrue(reader.next());
        assertFalse(reader.next());
    }

    /** Short reads, as an inflating zip stream returns, must not change where lines end. */
    public void testShortReads() throws IOException {
        byte[] data = "{\"a\":1}\r\n{\"bb\":22}\n{\"ccc\":333}\r".getBytes(StandardCharsets.UTF_8);
        InputStream oneByteAtATime =
                new ByteArrayInputStream(data) {
                    @Override
                    public synchronized int read(byte[] b, int off, int len) {
                        return super.read(b, off, Math.min(len, 1));
                    }
                };
        NdjsonLineReader reader = new NdjsonLineReader(oneByteAtATime, 4, 8);
        List<String> lines = new ArrayList<>();
        while (reader.next()) {
            lines.add(
                    new String(
                            reader.buffer(), reader.lineStart(), reader.lineLength(), StandardCharsets.UTF_8));
        }
        assertEquals(readAllWithBufferedReader(data), lines);
    }
}
