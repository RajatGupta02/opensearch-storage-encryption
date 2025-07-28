/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.opensearch.index.store.cipher.OpenSslNativeCipher;
import org.opensearch.index.store.iv.KeyIvResolver;

/**
 * A FileChannel wrapper that provides transparent AES-CTR encryption/decryption
 * for translog files with header-aware encryption.
 *
 * Key features:
 * - Leaves translog header unencrypted (first ~43+ bytes) for OpenSearch compatibility
 * - Encrypts only the data portion after the header
 * - Thread-safe with proper position tracking
 * - Unified key management with index files
 *
 * This approach ensures OpenSearch can read translog metadata while keeping
 * the actual translog operations encrypted.
 *
 * @opensearch.internal
 */
public class CryptoFileChannelWrapper extends FileChannel {

    private final FileChannel delegate;
    private final KeyIvResolver keyIvResolver;
    private final Path filePath;
    private final AtomicLong position;
    private final ReentrantReadWriteLock positionLock;
    private volatile boolean closed = false;

    // Thread-local buffer for efficient encryption/decryption
    private static final ThreadLocal<ByteBuffer> TEMP_BUFFER = ThreadLocal.withInitial(() -> ByteBuffer.allocate(16_384));

    // Header size constants
    private static final int ESTIMATED_HEADER_SIZE = 100; // Conservative estimate, actual is ~43+ bytes
    private volatile int actualHeaderSize = -1; // Will be determined dynamically

    // Constants for better consistency
    private static final int BUFFER_SIZE = 16_384;

    /**
     * Creates a new CryptoFileChannelWrapper that wraps the provided FileChannel.
     *
     * @param delegate the underlying FileChannel to wrap
     * @param keyIvResolver the key and IV resolver for encryption (unified with index files)
     * @param path the file path (used for logging and debugging)
     * @param options the file open options (used for logging and debugging)
     * @throws IOException if there is an error setting up the channel
     */
    public CryptoFileChannelWrapper(FileChannel delegate, KeyIvResolver keyIvResolver, Path path, Set<OpenOption> options)
        throws IOException {
        this.delegate = delegate;
        this.keyIvResolver = keyIvResolver;
        this.filePath = path;
        this.position = new AtomicLong(delegate.position());
        this.positionLock = new ReentrantReadWriteLock();
    }

    /**
     * Determines if the given position is within the header area.
     * Header area should not be encrypted.
     */
    private boolean isHeaderPosition(long pos) {
        if (actualHeaderSize > 0) {
            return pos < actualHeaderSize;
        }
        // Use conservative estimate if actual size not yet determined
        return pos < ESTIMATED_HEADER_SIZE;
    }

    /**
     * Determines the actual header size by examining the file name.
     * For translog files, we need to calculate the header size based on the translog UUID.
     */
    private int determineHeaderSize() {
        if (actualHeaderSize > 0) {
            return actualHeaderSize;
        }

        // For translog files, we need to read the header to determine its size
        // This is a bit tricky because we need to avoid infinite recursion
        // For now, use a conservative estimate
        String fileName = filePath.getFileName().toString();
        if (fileName.endsWith(".tlog")) {
            // Translog files have variable header sizes, but typically around 43-60 bytes
            // We'll use a conservative estimate and refine this later
            actualHeaderSize = 60;
        } else {
            // Non-translog files (.ckp) don't need encryption anyway
            actualHeaderSize = 0;
        }

        return actualHeaderSize;
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        return read(dst, position.get());
    }

    @Override
    public int read(ByteBuffer dst, long position) throws IOException {
        ensureOpen();

        if (dst.remaining() == 0) {
            return 0;
        }

        positionLock.writeLock().lock();
        try {
            // Read data from delegate
            int bytesRead = delegate.read(dst, position);
            if (bytesRead <= 0) {
                return bytesRead;
            }

            // Update position tracking for non-position-specific reads
            if (position == this.position.get()) {
                this.position.addAndGet(bytesRead);
            }

            // Determine header size
            int headerSize = determineHeaderSize();

            // If this read is entirely within the header, no decryption needed
            if (position + bytesRead <= headerSize) {
                return bytesRead;
            }

            // If this read starts within the header but extends beyond it
            if (position < headerSize && position + bytesRead > headerSize) {
                // Only decrypt the portion beyond the header
                int headerPortion = (int) (headerSize - position);
                int encryptedPortion = bytesRead - headerPortion;

                if (encryptedPortion > 0) {
                    // Get the encrypted data portion
                    byte[] encryptedData = new byte[encryptedPortion];
                    int originalPosition = dst.position();
                    dst.position(originalPosition - encryptedPortion);
                    dst.get(encryptedData);

                    // Decrypt the data using unified key resolver
                    try {
                        byte[] key = keyIvResolver.getDataKey().getEncoded();
                        byte[] iv = keyIvResolver.getIvBytes();
                        long encryptedPosition = position + headerPortion;
                        byte[] decryptedData = OpenSslNativeCipher.decrypt(key, iv, encryptedData, encryptedPosition);

                        // Put the decrypted data back into the buffer
                        dst.position(originalPosition - encryptedPortion);
                        dst.put(decryptedData);
                    } catch (Throwable e) {
                        throw new IOException("Failed to decrypt data at position " + (position + headerPortion), e);
                    }
                }

                return bytesRead;
            }

            // If this read is entirely beyond the header, decrypt all of it
            if (position >= headerSize) {
                try {
                    // Get the data that was just read
                    byte[] encryptedData = new byte[bytesRead];
                    int originalPosition = dst.position();
                    dst.position(originalPosition - bytesRead);
                    dst.get(encryptedData);

                    // Decrypt the data using unified key resolver
                    byte[] key = keyIvResolver.getDataKey().getEncoded();
                    byte[] iv = keyIvResolver.getIvBytes();
                    byte[] decryptedData = OpenSslNativeCipher.decrypt(key, iv, encryptedData, position);

                    // Put the decrypted data back into the buffer
                    dst.position(originalPosition - bytesRead);
                    dst.put(decryptedData);

                    return bytesRead;
                } catch (Throwable e) {
                    throw new IOException("Failed to decrypt data at position " + position, e);
                }
            }

            return bytesRead;
        } finally {
            positionLock.writeLock().unlock();
        }
    }

    @Override
    public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        ensureOpen();

        long totalBytesRead = 0;
        long currentPosition = position.get();

        for (int i = offset; i < offset + length && i < dsts.length; i++) {
            ByteBuffer dst = dsts[i];
            if (dst.remaining() > 0) {
                int bytesRead = read(dst, currentPosition + totalBytesRead);
                if (bytesRead <= 0) {
                    break;
                }
                totalBytesRead += bytesRead;
            }
        }

        if (totalBytesRead > 0) {
            position.addAndGet(totalBytesRead);
        }

        return totalBytesRead;
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
        long currentPosition = position.get();
        int bytesWritten = write(src, currentPosition);
        if (bytesWritten > 0) {
            position.addAndGet(bytesWritten);
        }
        return bytesWritten;
    }

    @Override
    public int write(ByteBuffer src, long position) throws IOException {
        ensureOpen();

        if (src.remaining() == 0) {
            return 0;
        }

        positionLock.writeLock().lock();
        try {
            // Determine header size
            int headerSize = determineHeaderSize();

            // If this write is entirely within the header, no encryption needed
            if (position + src.remaining() <= headerSize) {
                return delegate.write(src, position);
            }

            // If this write starts within the header but extends beyond it
            if (position < headerSize && position + src.remaining() > headerSize) {
                // Split the write into header and data portions
                int headerPortion = (int) (headerSize - position);
                int dataPortion = src.remaining() - headerPortion;

                // Write header portion without encryption
                ByteBuffer headerBuffer = ByteBuffer.allocate(headerPortion);
                src.get(headerBuffer.array());
                headerBuffer.flip();
                int headerBytesWritten = delegate.write(headerBuffer, position);

                // Write data portion with encryption
                if (dataPortion > 0 && headerBytesWritten == headerPortion) {
                    byte[] plainData = new byte[dataPortion];
                    src.get(plainData);

                    // Encrypt the data using unified key resolver
                    try {
                        byte[] key = keyIvResolver.getDataKey().getEncoded();
                        byte[] iv = keyIvResolver.getIvBytes();
                        long encryptedPosition = position + headerPortion;
                        byte[] encryptedData = OpenSslNativeCipher.encrypt(key, iv, plainData, encryptedPosition);

                        // Write the encrypted data
                        ByteBuffer encryptedBuffer = ByteBuffer.wrap(encryptedData);
                        int dataBytesWritten = delegate.write(encryptedBuffer, encryptedPosition);

                        return headerBytesWritten + dataBytesWritten;
                    } catch (Throwable e) {
                        throw new IOException("Failed to encrypt data at position " + (position + headerPortion), e);
                    }
                }

                return headerBytesWritten;
            }

            // If this write is entirely beyond the header, encrypt all of it
            if (position >= headerSize) {
                try {
                    // Get the data to encrypt
                    byte[] plainData = new byte[src.remaining()];
                    src.get(plainData);

                    // Encrypt the data using unified key resolver
                    byte[] key = keyIvResolver.getDataKey().getEncoded();
                    byte[] iv = keyIvResolver.getIvBytes();
                    byte[] encryptedData = OpenSslNativeCipher.encrypt(key, iv, plainData, position);

                    // Write the encrypted data
                    ByteBuffer encryptedBuffer = ByteBuffer.wrap(encryptedData);
                    int bytesWritten = delegate.write(encryptedBuffer, position);

                    return bytesWritten;
                } catch (Throwable e) {
                    throw new IOException("Failed to encrypt data at position " + position, e);
                }
            }

            // Fallback to direct write (shouldn't reach here)
            return delegate.write(src, position);
        } finally {
            positionLock.writeLock().unlock();
        }
    }

    @Override
    public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
        ensureOpen();

        long totalBytesWritten = 0;
        long currentPosition = position.get();

        for (int i = offset; i < offset + length && i < srcs.length; i++) {
            ByteBuffer src = srcs[i];
            if (src.remaining() > 0) {
                int bytesWritten = write(src, currentPosition + totalBytesWritten);
                if (bytesWritten <= 0) {
                    break;
                }
                totalBytesWritten += bytesWritten;
            }
        }

        if (totalBytesWritten > 0) {
            position.addAndGet(totalBytesWritten);
        }

        return totalBytesWritten;
    }

    @Override
    public long position() throws IOException {
        ensureOpen();
        return position.get();
    }

    @Override
    public FileChannel position(long newPosition) throws IOException {
        ensureOpen();
        delegate.position(newPosition);
        position.set(newPosition);
        return this;
    }

    @Override
    public long size() throws IOException {
        ensureOpen();
        return delegate.size();
    }

    @Override
    public FileChannel truncate(long size) throws IOException {
        ensureOpen();
        delegate.truncate(size);
        long currentPosition = position.get();
        if (currentPosition > size) {
            position.set(size);
        }
        return this;
    }

    @Override
    public void force(boolean metaData) throws IOException {
        ensureOpen();
        delegate.force(metaData);
    }

    @Override
    public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
        ensureOpen();

        // For encrypted files, we need to decrypt data during transfer
        // This is less efficient but ensures data is properly decrypted
        long transferred = 0;
        long remaining = count;
        ByteBuffer buffer = ByteBuffer.allocate(8192);

        while (remaining > 0 && transferred < count) {
            buffer.clear();
            int toRead = (int) Math.min(buffer.remaining(), remaining);
            buffer.limit(toRead);

            int bytesRead = read(buffer, position + transferred);
            if (bytesRead <= 0) {
                break;
            }

            buffer.flip();
            int bytesWritten = target.write(buffer);
            transferred += bytesWritten;
            remaining -= bytesWritten;

            if (bytesWritten < bytesRead) {
                break;
            }
        }

        return transferred;
    }

    @Override
    public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
        ensureOpen();

        // For encrypted files, we need to encrypt data during transfer
        long transferred = 0;
        long remaining = count;
        ByteBuffer buffer = ByteBuffer.allocate(8192);

        while (remaining > 0 && transferred < count) {
            buffer.clear();
            int toRead = (int) Math.min(buffer.remaining(), remaining);
            buffer.limit(toRead);

            int bytesRead = src.read(buffer);
            if (bytesRead <= 0) {
                break;
            }

            buffer.flip();
            int bytesWritten = write(buffer, position + transferred);
            transferred += bytesWritten;
            remaining -= bytesWritten;

            if (bytesWritten < bytesRead) {
                break;
            }
        }

        return transferred;
    }

    @Override
    public FileLock lock(long position, long size, boolean shared) throws IOException {
        ensureOpen();
        return delegate.lock(position, size, shared);
    }

    @Override
    public FileLock tryLock(long position, long size, boolean shared) throws IOException {
        ensureOpen();
        return delegate.tryLock(position, size, shared);
    }

    @Override
    public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
        ensureOpen();

        // For encrypted files, we cannot support memory mapping directly
        // because the mapped memory would contain encrypted data
        throw new UnsupportedOperationException(
            "Memory mapping is not supported for encrypted translog files. "
                + "Encrypted files require data to be decrypted during read operations."
        );
    }

    @Override
    protected void implCloseChannel() throws IOException {
        if (!closed) {
            closed = true;
            delegate.close();
        }
    }

    private void ensureOpen() throws ClosedChannelException {
        if (closed || !delegate.isOpen()) {
            throw new ClosedChannelException();
        }
    }

    /**
     * Gets the underlying delegate FileChannel.
     *
     * @return the delegate FileChannel
     */
    public FileChannel getDelegate() {
        return delegate;
    }

    /**
     * Gets the determined header size for this translog file.
     *
     * @return the header size in bytes
     */
    public int getHeaderSize() {
        return determineHeaderSize();
    }
}
