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
import org.apache.lucene.codecs.CodecUtil;
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

    // Constants for better consistency
    private static final int BUFFER_SIZE = 16_384;

    // Thread-local buffer for efficient encryption/decryption operations
    private static final ThreadLocal<byte[]> TEMP_BYTE_ARRAY = ThreadLocal.withInitial(() -> new byte[BUFFER_SIZE]);

    // Header size - calculated exactly using TranslogHeader.headerSizeInBytes()
    private volatile int actualHeaderSize = -1;

    // TranslogHeader constants replicated to avoid cross-classloader access
    private static final String TRANSLOG_CODEC = "translog";
    private static final int VERSION_PRIMARY_TERM = 3;
    private static final int CURRENT_VERSION = VERSION_PRIMARY_TERM;

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
     * Determines the exact header size using local calculation to avoid cross-classloader access.
     * This replicates the exact same logic as TranslogHeader.headerSizeInBytes() method.
     */
    private int determineHeaderSize() {
        if (actualHeaderSize > 0) {
            return actualHeaderSize;
        }

        String fileName = filePath.getFileName().toString();
        if (fileName.endsWith(".tlog")) {
            actualHeaderSize = calculateTranslogHeaderSize(translogUUID);
            logger.debug("Calculated exact header size: {} bytes for {} with UUID: {}", actualHeaderSize, filePath, translogUUID);
        } else {
            // Non-translog files (.ckp) don't need encryption anyway
            actualHeaderSize = 0;
            logger.debug("Non-translog file {}, header size: 0", filePath);
        }

        return actualHeaderSize;
    }

    /**
     * Local implementation of TranslogHeader.headerSizeInBytes() to avoid cross-classloader access issues.
     * This replicates the exact same calculation as the original method.
     *
     * @param translogUUID the translog UUID
     * @return the header size in bytes
     */
    private static int calculateTranslogHeaderSize(String translogUUID) {
        // Replicate: headerSizeInBytes(CURRENT_VERSION, new BytesRef(translogUUID).length)
        int uuidLength = translogUUID.getBytes().length;

        // Replicate the internal calculation
        int size = CodecUtil.headerLength(TRANSLOG_CODEC); // Lucene codec header
        size += Integer.BYTES + uuidLength; // uuid length field + uuid bytes

        // VERSION_PRIMARY_TERM = 3, CURRENT_VERSION = 3
        if (CURRENT_VERSION >= VERSION_PRIMARY_TERM) {
            size += Long.BYTES;    // primary term
            size += Integer.BYTES; // checksum
        }

        return size;
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
                    // Get the encrypted data portion using ThreadLocal buffer
                    byte[] encryptedData = getTempByteArray(encryptedPortion);
                    int originalPosition = dst.position();
                    dst.position(originalPosition - encryptedPortion);
                    dst.get(encryptedData, 0, encryptedPortion);

                    // Decrypt the data using unified key resolver
                    try {
                        byte[] key = keyIvResolver.getDataKey().getEncoded();
                        byte[] iv = keyIvResolver.getIvBytes();
                        long encryptedPosition = position + headerPortion;

                        // END-TO-END TEST: Log encrypted data read from disk
                        logger
                            .error(
                                "DECRYPT TEST: read boundary - pos={}, size={}, encrypted=[{}]",
                                encryptedPosition,
                                encryptedPortion,
                                dataToHex(encryptedData, 16)
                            );

                        // Create exact-sized array for decryption (OpenSslNativeCipher requires exact size)
                        byte[] exactEncryptedData = java.util.Arrays.copyOf(encryptedData, encryptedPortion);
                        byte[] decryptedData = OpenSslNativeCipher.decrypt(key, iv, exactEncryptedData, encryptedPosition);

                        // END-TO-END TEST: Log decrypted data after decryption
                        logger
                            .error(
                                "DECRYPT TEST: read boundary - pos={}, size={}, decrypted=[{}]",
                                encryptedPosition,
                                encryptedPortion,
                                dataToHex(decryptedData, 16)
                            );

                        // Put the decrypted data back into the buffer
                        dst.position(originalPosition - encryptedPortion);
                        dst.put(decryptedData);

                        // Clear sensitive data
                        clearSensitiveData(encryptedData, encryptedPortion);
                        clearSensitiveData(exactEncryptedData, exactEncryptedData.length);
                        clearSensitiveData(decryptedData, decryptedData.length);
                    } catch (Throwable e) {
                        logger.error("CRYPTO DEBUG: read() decrypt FAILED at pos={}", position + headerPortion, e);
                        // Clear sensitive data even on error
                        clearSensitiveData(encryptedData, encryptedPortion);
                        throw new IOException("Failed to decrypt data at position " + (position + headerPortion), e);
                    }
                }

                return bytesRead;
            }

            // If this read is entirely beyond the header, decrypt all of it
            if (position >= headerSize) {
                try {
                    // Get the data that was just read using ThreadLocal buffer
                    byte[] encryptedData = getTempByteArray(bytesRead);
                    int originalPosition = dst.position();
                    dst.position(originalPosition - bytesRead);
                    dst.get(encryptedData, 0, bytesRead);

                    // Decrypt the data using unified key resolver
                    byte[] key = keyIvResolver.getDataKey().getEncoded();
                    byte[] iv = keyIvResolver.getIvBytes();

                    // END-TO-END TEST: Log encrypted data read from disk
                    logger
                        .error(
                            "DECRYPT TEST: read full - pos={}, size={}, encrypted=[{}]",
                            position,
                            bytesRead,
                            dataToHex(encryptedData, 16)
                        );

                    // Create exact-sized array for decryption
                    byte[] exactEncryptedData = java.util.Arrays.copyOf(encryptedData, bytesRead);
                    byte[] decryptedData = OpenSslNativeCipher.decrypt(key, iv, exactEncryptedData, position);

                    // END-TO-END TEST: Log decrypted data after decryption
                    logger
                        .error(
                            "DECRYPT TEST: read full - pos={}, size={}, decrypted=[{}]",
                            position,
                            bytesRead,
                            dataToHex(decryptedData, 16)
                        );

                    // Put the decrypted data back into the buffer
                    dst.position(originalPosition - bytesRead);
                    dst.put(decryptedData);

                    // Clear sensitive data
                    clearSensitiveData(encryptedData, bytesRead);
                    clearSensitiveData(exactEncryptedData, exactEncryptedData.length);
                    clearSensitiveData(decryptedData, decryptedData.length);

                    return bytesRead;
                } catch (Throwable e) {
                    logger.error("CRYPTO DEBUG: read() decrypt FAILED at pos={}", position, e);
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
                    // Use ThreadLocal buffer for plain data
                    byte[] plainData = getTempByteArray(dataPortion);
                    src.get(plainData, 0, dataPortion);

                    // Encrypt the data using unified key resolver
                    try {
                        byte[] key = keyIvResolver.getDataKey().getEncoded();
                        byte[] iv = keyIvResolver.getIvBytes();
                        long encryptedPosition = position + headerPortion;

                        // END-TO-END TEST: Log plaintext data before encryption
                        logger
                            .error(
                                "ENCRYPT TEST: write boundary - pos={}, size={}, plaintext=[{}]",
                                encryptedPosition,
                                dataPortion,
                                dataToHex(plainData, 16)
                            );

                        // Create exact-sized array for encryption
                        byte[] exactPlainData = java.util.Arrays.copyOf(plainData, dataPortion);
                        byte[] encryptedData = OpenSslNativeCipher.encrypt(key, iv, exactPlainData, encryptedPosition);

                        // END-TO-END TEST: Log encrypted data after encryption
                        logger
                            .error(
                                "ENCRYPT TEST: write boundary - pos={}, size={}, encrypted=[{}]",
                                encryptedPosition,
                                dataPortion,
                                dataToHex(encryptedData, 16)
                            );

                        // ROUND-TRIP TEST: Immediately test decryption to verify integrity
                        try {
                            byte[] testDecrypted = OpenSslNativeCipher.decrypt(key, iv, encryptedData, encryptedPosition);
                            boolean roundTripOK = java.util.Arrays.equals(exactPlainData, testDecrypted);
                            logger
                                .error(
                                    "ROUND-TRIP TEST: write boundary - pos={}, size={}, success=[{}]",
                                    encryptedPosition,
                                    dataPortion,
                                    roundTripOK
                                );
                            if (!roundTripOK) {
                                logger
                                    .error(
                                        "ROUND-TRIP FAILURE: Original=[{}], Decrypted=[{}]",
                                        dataToHex(exactPlainData, 16),
                                        dataToHex(testDecrypted, 16)
                                    );
                            }
                            clearSensitiveData(testDecrypted, testDecrypted.length);
                        } catch (Exception rtException) {
                            logger
                                .error(
                                    "ROUND-TRIP ERROR: write boundary - pos={}, size={}, error={}",
                                    encryptedPosition,
                                    dataPortion,
                                    rtException.getMessage()
                                );
                        }

                        // Write the encrypted data
                        ByteBuffer encryptedBuffer = ByteBuffer.wrap(encryptedData);
                        int dataBytesWritten = delegate.write(encryptedBuffer, encryptedPosition);

                        // Clear sensitive data
                        clearSensitiveData(plainData, dataPortion);
                        clearSensitiveData(exactPlainData, exactPlainData.length);

                        return headerBytesWritten + dataBytesWritten;
                    } catch (Throwable e) {
                        logger.error("CRYPTO DEBUG: write() encrypt FAILED at pos={}", position + headerPortion, e);
                        // Clear sensitive data even on error
                        clearSensitiveData(plainData, dataPortion);
                        throw new IOException("Failed to encrypt data at position " + (position + headerPortion), e);
                    }
                }

                return headerBytesWritten;
            }

            // If this write is entirely beyond the header, encrypt all of it
            if (position >= headerSize) {
                try {
                    // Get the data to encrypt using ThreadLocal buffer
                    int dataSize = src.remaining();
                    byte[] plainData = getTempByteArray(dataSize);
                    src.get(plainData, 0, dataSize);

                    // Encrypt the data using unified key resolver
                    byte[] key = keyIvResolver.getDataKey().getEncoded();
                    byte[] iv = keyIvResolver.getIvBytes();

                    // END-TO-END TEST: Log plaintext data before encryption
                    logger
                        .error("ENCRYPT TEST: write full - pos={}, size={}, plaintext=[{}]", position, dataSize, dataToHex(plainData, 16));

                    // Create exact-sized array for encryption
                    byte[] exactPlainData = java.util.Arrays.copyOf(plainData, dataSize);
                    byte[] encryptedData = OpenSslNativeCipher.encrypt(key, iv, exactPlainData, position);

                    // END-TO-END TEST: Log encrypted data after encryption
                    logger
                        .error(
                            "ENCRYPT TEST: write full - pos={}, size={}, encrypted=[{}]",
                            position,
                            dataSize,
                            dataToHex(encryptedData, 16)
                        );

                    // ROUND-TRIP TEST: Immediately test decryption to verify integrity
                    try {
                        byte[] testDecrypted = OpenSslNativeCipher.decrypt(key, iv, encryptedData, position);
                        boolean roundTripOK = java.util.Arrays.equals(exactPlainData, testDecrypted);
                        logger.error("ROUND-TRIP TEST: write full - pos={}, size={}, success=[{}]", position, dataSize, roundTripOK);
                        if (!roundTripOK) {
                            logger
                                .error(
                                    "ROUND-TRIP FAILURE: Original=[{}], Decrypted=[{}]",
                                    dataToHex(exactPlainData, 16),
                                    dataToHex(testDecrypted, 16)
                                );
                        }
                        clearSensitiveData(testDecrypted, testDecrypted.length);
                    } catch (Exception rtException) {
                        logger
                            .error(
                                "ROUND-TRIP ERROR: write full - pos={}, size={}, error={}",
                                position,
                                dataSize,
                                rtException.getMessage()
                            );
                    }

                    // Write the encrypted data
                    ByteBuffer encryptedBuffer = ByteBuffer.wrap(encryptedData);
                    int bytesWritten = delegate.write(encryptedBuffer, position);

                    // Clear sensitive data
                    clearSensitiveData(plainData, dataSize);
                    clearSensitiveData(exactPlainData, exactPlainData.length);

                    return bytesWritten;
                } catch (Throwable e) {
                    logger.error("CRYPTO DEBUG: write() encrypt FAILED at pos={}", position, e);
                    throw new IOException("Failed to encrypt data at position " + position, e);
                }
            }
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
     * Gets a temporary byte array from ThreadLocal storage, expanding if needed.
     * This reduces GC pressure by reusing arrays across operations.
     *
     * @param minSize the minimum required size
     * @return a byte array of at least minSize capacity
     */
    private static byte[] getTempByteArray(int minSize) {
        byte[] array = TEMP_BYTE_ARRAY.get();
        if (array.length < minSize) {
            // Expand the array, use next power of 2 or minSize, whichever is larger
            int newSize = Math.max(minSize, Integer.highestOneBit(minSize - 1) << 1);
            array = new byte[newSize];
            TEMP_BYTE_ARRAY.set(array);
        }
        return array;
    }

    /**
     * Clears sensitive data from the temporary array after use.
     * This ensures encryption keys and plaintext don't linger in memory.
     *
     * @param array the array to clear
     * @param length the number of bytes to clear from the start
     */
    private static void clearSensitiveData(byte[] array, int length) {
        if (array != null && length > 0) {
            int clearLength = Math.min(length, array.length);
            java.util.Arrays.fill(array, 0, clearLength, (byte) 0);
        }
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
     * Helper method to convert data to hex string for end-to-end testing.
     * Shows first 16 bytes of actual data being encrypted/decrypted.
     */
    private static String dataToHex(byte[] data, int maxBytes) {
        if (data == null || data.length == 0) {
            return "[empty]";
        }
        int bytesToShow = Math.min(maxBytes, data.length);
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < bytesToShow; i++) {
            String hexByte = Integer.toHexString(0xFF & data[i]);
            if (hexByte.length() == 1) {
                hex.append('0');
            }
            hex.append(hexByte);
        }
        if (data.length > maxBytes) {
            hex.append("...[+").append(data.length - maxBytes).append(" more]");
        }
        return hex.toString();
    }
}
