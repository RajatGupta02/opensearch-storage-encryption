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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.cipher.OpenSslNativeCipher;
import org.opensearch.index.store.iv.KeyIvResolver;

/**
 * A FileChannel wrapper that provides transparent AES-CTR encryption/decryption
 * for translog files with header-aware encryption.
 *
 * This approach ensures OpenSearch can read translog metadata while keeping
 * the actual translog operations encrypted.
 *
 * @opensearch.internal
 */
public class CryptoFileChannelWrapper extends FileChannel {

    private static final Logger logger = LogManager.getLogger(CryptoFileChannelWrapper.class);

    private final FileChannel delegate;
    private final KeyIvResolver keyIvResolver;
    private final Path filePath;
    private final String translogUUID;
    private final AtomicLong position;
    private final ReentrantReadWriteLock positionLock;
    private volatile boolean closed = false;

    // Thread-local buffer for efficient encryption/decryption
    private static final ThreadLocal<ByteBuffer> TEMP_BUFFER = ThreadLocal.withInitial(() -> ByteBuffer.allocate(16_384));

    // Header size - calculated exactly using TranslogHeader.headerSizeInBytes()
    private volatile int actualHeaderSize = -1;

    // Constants for better consistency
    private static final int BUFFER_SIZE = 16_384;

    /**
     * Creates a new CryptoFileChannelWrapper that wraps the provided FileChannel.
     *
     * @param delegate the underlying FileChannel to wrap
     * @param keyIvResolver the key and IV resolver for encryption (unified with index files)
     * @param path the file path (used for logging and debugging)
     * @param options the file open options (used for logging and debugging)
     * @param translogUUID the translog UUID for exact header size calculation
     * @throws IOException if there is an error setting up the channel
     */
    public CryptoFileChannelWrapper(
        FileChannel delegate,
        KeyIvResolver keyIvResolver,
        Path path,
        Set<OpenOption> options,
        String translogUUID
    )
        throws IOException {
        if (translogUUID == null) {
            throw new IllegalArgumentException("translogUUID is required for exact header size calculation");
        }
        this.delegate = delegate;
        this.keyIvResolver = keyIvResolver;
        this.filePath = path;
        this.translogUUID = translogUUID;
        this.position = new AtomicLong(delegate.position());
        this.positionLock = new ReentrantReadWriteLock();
    }

    /**
     * Determines the exact header size using OpenSearch's TranslogHeader.headerSizeInBytes() method.
     * This eliminates ALL file reading and estimation - uses pure calculation based on UUID.
     */
    private int determineHeaderSize() {
        if (actualHeaderSize > 0) {
            return actualHeaderSize;
        }

        String fileName = filePath.getFileName().toString();
        if (fileName.endsWith(".tlog")) {
            actualHeaderSize = TranslogHeader.headerSizeInBytes(translogUUID);
            logger.debug("Calculated exact header size: {} bytes for {} with UUID: {}", actualHeaderSize, filePath, translogUUID);
        } else {
            // Non-translog files (.ckp) don't need encryption anyway
            actualHeaderSize = 0;
            logger.debug("Non-translog file {}, header size: 0", filePath);
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

            // CRITICAL DEBUG: Log every write operation
            logger
                .error(
                    "CRYPTO DEBUG: write() called - position={}, dataSize={}, headerSize={}, filePath={}",
                    position,
                    src.remaining(),
                    headerSize,
                    filePath
                );

            // If this write is entirely within the header, no encryption needed
            if (position + src.remaining() <= headerSize) {
                logger.error("CRYPTO DEBUG: Writing to header area - position={}, size={}, no encryption", position, src.remaining());
                return delegate.write(src, position);
            }

            // If this write starts within the header but extends beyond it
            if (position < headerSize && position + src.remaining() > headerSize) {
                logger
                    .error("CRYPTO DEBUG: Write spans header boundary - position={}, headerSize={}, splitting write", position, headerSize);

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

                    logger.error("CRYPTO DEBUG: Encrypting data portion - size={}, position={}", dataPortion, position + headerPortion);

                    // LOG PLAINTEXT DATA BEFORE ENCRYPTION
                    logger
                        .error(
                            "CRYPTO DEBUG: PLAINTEXT DATA (boundary span) - position={}, size={}, preview=[{}], hex=[{}]",
                            position + headerPortion,
                            plainData.length,
                            bytesToSafeString(plainData, 100),
                            bytesToHex(plainData, 0, Math.min(50, plainData.length))
                        );

                    // Encrypt the data using unified key resolver
                    try {
                        byte[] key = keyIvResolver.getDataKey().getEncoded();
                        byte[] iv = keyIvResolver.getIvBytes();
                        long encryptedPosition = position + headerPortion;
                        byte[] encryptedData = OpenSslNativeCipher.encrypt(key, iv, plainData, encryptedPosition);

                        // LOG ENCRYPTED DATA AFTER ENCRYPTION
                        logger
                            .error(
                                "CRYPTO DEBUG: ENCRYPTED DATA (boundary span) - position={}, plainSize={}, encryptedSize={}, encryptedHex=[{}]",
                                encryptedPosition,
                                plainData.length,
                                encryptedData.length,
                                bytesToHex(encryptedData, 0, Math.min(50, encryptedData.length))
                            );

                        logger
                            .error(
                                "CRYPTO DEBUG: Encryption successful - plainSize={}, encryptedSize={}",
                                plainData.length,
                                encryptedData.length
                            );

                        // Write the encrypted data
                        ByteBuffer encryptedBuffer = ByteBuffer.wrap(encryptedData);
                        int dataBytesWritten = delegate.write(encryptedBuffer, encryptedPosition);

                        return headerBytesWritten + dataBytesWritten;
                    } catch (Throwable e) {
                        logger.error("CRYPTO DEBUG: Encryption FAILED - error={}", e.getMessage(), e);
                        throw new IOException("Failed to encrypt data at position " + (position + headerPortion), e);
                    }
                }

                return headerBytesWritten;
            }

            // If this write is entirely beyond the header, encrypt all of it
            if (position >= headerSize) {
                logger.error("CRYPTO DEBUG: Writing beyond header - position={}, size={}, encrypting all data", position, src.remaining());

                try {
                    // Get the data to encrypt
                    byte[] plainData = new byte[src.remaining()];
                    src.get(plainData);

                    logger.error("CRYPTO DEBUG: About to encrypt data - size={}, position={}", plainData.length, position);

                    // LOG PLAINTEXT DATA BEFORE ENCRYPTION
                    logger
                        .error(
                            "CRYPTO DEBUG: PLAINTEXT DATA (beyond header) - position={}, size={}, preview=[{}], hex=[{}]",
                            position,
                            plainData.length,
                            bytesToSafeString(plainData, 100),
                            bytesToHex(plainData, 0, Math.min(50, plainData.length))
                        );

                    // Encrypt the data using unified key resolver
                    byte[] key = keyIvResolver.getDataKey().getEncoded();
                    byte[] iv = keyIvResolver.getIvBytes();
                    byte[] encryptedData = OpenSslNativeCipher.encrypt(key, iv, plainData, position);

                    // LOG ENCRYPTED DATA AFTER ENCRYPTION
                    logger
                        .error(
                            "CRYPTO DEBUG: ENCRYPTED DATA (beyond header) - position={}, plainSize={}, encryptedSize={}, encryptedHex=[{}]",
                            position,
                            plainData.length,
                            encryptedData.length,
                            bytesToHex(encryptedData, 0, Math.min(50, encryptedData.length))
                        );

                    logger
                        .error(
                            "CRYPTO DEBUG: Encryption successful - plainSize={}, encryptedSize={}",
                            plainData.length,
                            encryptedData.length
                        );

                    // Write the encrypted data
                    ByteBuffer encryptedBuffer = ByteBuffer.wrap(encryptedData);
                    int bytesWritten = delegate.write(encryptedBuffer, position);

                    logger.error("CRYPTO DEBUG: Encrypted data written - bytesWritten={}", bytesWritten);
                    return bytesWritten;
                } catch (Throwable e) {
                    logger.error("CRYPTO DEBUG: Encryption FAILED - error={}", e.getMessage(), e);
                    throw new IOException("Failed to encrypt data at position " + position, e);
                }
            }

            // Fallback to direct write (THIS SHOULD NEVER HAPPEN!)
            logger
                .error(
                    "CRYPTO DEBUG: FALLBACK WRITE - THIS IS A BUG! position={}, headerSize={}, size={}",
                    position,
                    headerSize,
                    src.remaining()
                );
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
     * Uses exact calculation based on translogUUID - no exceptions possible.
     *
     * @return the header size in bytes
     */
    public int getHeaderSize() {
        return determineHeaderSize();
    }

    /**
     * Helper method to convert bytes to hex string for debug logging.
     */
    private static String bytesToHex(byte[] bytes, int offset, int length) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder hexString = new StringBuilder();
        int end = Math.min(offset + length, bytes.length);
        for (int i = offset; i < end; i++) {
            String hex = Integer.toHexString(0xFF & bytes[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Helper method to safely convert bytes to string for debug logging.
     */
    private static String bytesToSafeString(byte[] bytes, int maxLength) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        int length = Math.min(maxLength, bytes.length);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            byte b = bytes[i];
            if (b >= 32 && b <= 126) { // Printable ASCII
                sb.append((char) b);
            } else {
                sb.append("\\x").append(String.format("%02x", b & 0xFF));
            }
        }
        if (bytes.length > maxLength) {
            sb.append("...[truncated]");
        }
        return sb.toString();
    }
}
