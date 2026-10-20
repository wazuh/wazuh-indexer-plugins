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

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Reads the lines of an NDJSON stream as byte ranges of one reusable buffer.
 *
 * <p>A snapshot holds hundreds of thousands of lines, a few of them several megabytes long. Reading
 * them as {@code String}s copies every line several times (the reader's growing builder, the
 * string, then its UTF-8 encoding for indexing), and the copies of the long lines are large enough
 * to be allocated straight into the old generation, which is what pushes a small heap over the
 * parent circuit breaker during a first sync. This reader hands out each line in place instead:
 * {@link #buffer()}, {@link #lineStart()} and {@link #lineLength()} describe the current line, and
 * stay valid only until the next call to {@link #next()}.
 *
 * <p>The buffer grows to fit the longest line seen. Once a line longer than {@code
 * maxRetainedCapacity} has been consumed, the buffer goes back to its initial size, so a single
 * outsized line does not stay pinned for the rest of the load.
 *
 * <p>Lines end at {@code \n}, {@code \r} or {@code \r\n}, as with {@link
 * java.io.BufferedReader#readLine()}. A last line without a terminator is returned; the terminator
 * after the last line does not produce an empty one.
 */
final class NdjsonLineReader {
    /** Initial buffer size: several lines of a typical snapshot. */
    static final int DEFAULT_INITIAL_CAPACITY = 64 * 1024;

    /** Largest buffer kept between lines. */
    static final int DEFAULT_MAX_RETAINED_CAPACITY = 1024 * 1024;

    /** Largest array size the JVM reliably allocates. */
    private static final int MAX_ARRAY_SIZE = Integer.MAX_VALUE - 8;

    private final InputStream in;
    private final int initialCapacity;
    private final int maxRetainedCapacity;

    private byte[] buf;

    /** Start of the bytes not consumed yet. */
    private int pos;

    /** End of the bytes read from the stream. */
    private int limit;

    private int lineStart;
    private int lineLength;

    /** Whether the last line ended at {@code \r}, so a {@code \n} right after it is skipped. */
    private boolean skipLf;

    private boolean eof;

    /**
     * Creates a reader with the default buffer sizes.
     *
     * @param in The stream to read. The caller closes it.
     */
    NdjsonLineReader(InputStream in) {
        this(in, DEFAULT_INITIAL_CAPACITY, DEFAULT_MAX_RETAINED_CAPACITY);
    }

    /**
     * Creates a reader.
     *
     * @param in The stream to read. The caller closes it.
     * @param initialCapacity The initial buffer size.
     * @param maxRetainedCapacity The largest buffer kept once the line that needed it is consumed.
     */
    NdjsonLineReader(InputStream in, int initialCapacity, int maxRetainedCapacity) {
        this.in = in;
        this.initialCapacity = initialCapacity;
        this.maxRetainedCapacity = Math.max(initialCapacity, maxRetainedCapacity);
        this.buf = new byte[initialCapacity];
    }

    /**
     * Advances to the next line.
     *
     * @return {@code false} at the end of the stream.
     * @throws IOException If the stream cannot be read, or a line does not fit in an array.
     */
    boolean next() throws IOException {
        this.releaseOutsizedBuffer();

        if (this.skipLf) {
            this.skipLf = false;
            if (this.pos == this.limit && !this.fill()) {
                return false;
            }
            if (this.buf[this.pos] == '\n') {
                this.pos++;
            }
        }

        int scanFrom = this.pos;
        while (true) {
            for (int i = scanFrom; i < this.limit; i++) {
                byte b = this.buf[i];
                if (b == '\n' || b == '\r') {
                    this.lineStart = this.pos;
                    this.lineLength = i - this.pos;
                    this.pos = i + 1;
                    this.skipLf = b == '\r';
                    return true;
                }
            }
            int scanned = this.limit - this.pos;
            if (!this.fill()) {
                if (this.limit > this.pos) {
                    this.lineStart = this.pos;
                    this.lineLength = this.limit - this.pos;
                    this.pos = this.limit;
                    return true;
                }
                return false;
            }
            scanFrom = this.pos + scanned;
        }
    }

    /**
     * Returns the buffer holding the current line.
     *
     * @return The buffer. Valid until the next call to {@link #next()}.
     */
    byte[] buffer() {
        return this.buf;
    }

    /**
     * Returns where the current line starts in {@link #buffer()}.
     *
     * @return The offset of the first byte of the line.
     */
    int lineStart() {
        return this.lineStart;
    }

    /**
     * Returns the length of the current line, without its terminator.
     *
     * @return The number of bytes in the line.
     */
    int lineLength() {
        return this.lineLength;
    }

    /**
     * Returns the current buffer size. For tests.
     *
     * @return The capacity of the buffer.
     */
    int capacity() {
        return this.buf.length;
    }

    /**
     * Reads more bytes after the buffered ones, moving the unconsumed bytes to the front of the
     * buffer or growing it to make room.
     *
     * @return {@code false} at the end of the stream.
     */
    private boolean fill() throws IOException {
        if (this.eof) {
            return false;
        }
        if (this.pos > 0) {
            int pending = this.limit - this.pos;
            System.arraycopy(this.buf, this.pos, this.buf, 0, pending);
            this.pos = 0;
            this.limit = pending;
        }
        if (this.limit == this.buf.length) {
            if (this.buf.length >= MAX_ARRAY_SIZE) {
                throw new IOException("Snapshot line longer than " + MAX_ARRAY_SIZE + " bytes");
            }
            int grown = (int) Math.min((long) this.buf.length * 2, MAX_ARRAY_SIZE);
            this.buf = Arrays.copyOf(this.buf, grown);
        }
        int read = this.in.read(this.buf, this.limit, this.buf.length - this.limit);
        if (read < 0) {
            this.eof = true;
            return false;
        }
        this.limit += read;
        return true;
    }

    /**
     * Goes back to a buffer of the initial size once the line that needed a bigger one is consumed,
     * keeping the bytes already read ahead.
     */
    private void releaseOutsizedBuffer() {
        int pending = this.limit - this.pos;
        if (this.buf.length > this.maxRetainedCapacity && pending <= this.initialCapacity) {
            byte[] smaller = new byte[this.initialCapacity];
            System.arraycopy(this.buf, this.pos, smaller, 0, pending);
            this.buf = smaller;
            this.pos = 0;
            this.limit = pending;
        }
    }
}
