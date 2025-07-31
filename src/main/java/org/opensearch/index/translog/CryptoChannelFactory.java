/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.iv.KeyIvResolver;

/**
 * A ChannelFactory implementation that creates FileChannels with transparent
 * AES-CTR encryption/decryption for translog files.
 *
 * This factory determines whether to apply encryption based on the file extension:
 * - .tlog files: Encrypted using AES-CTR
 * - .ckp files: Not encrypted (checkpoint metadata)
 *
 * Updated to use unified KeyIvResolver (same as index files) for consistent
 * key management across all encrypted components.
 *
 * @opensearch.internal
 */
public class CryptoChannelFactory implements ChannelFactory {

    private static final Logger logger = LogManager.getLogger(CryptoChannelFactory.class);

    private final KeyIvResolver keyIvResolver;
    private final String translogUUID;

    /**
     * Creates a new CryptoChannelFactory.
     *
     * @param keyIvResolver the key and IV resolver for encryption keys (unified with index files)
     * @param translogUUID the translog UUID for exact header size calculation
     */
    public CryptoChannelFactory(KeyIvResolver keyIvResolver, String translogUUID) {
        if (translogUUID == null) {
            throw new IllegalArgumentException("translogUUID is required for exact header size calculation");
        }
        this.keyIvResolver = keyIvResolver;
        this.translogUUID = translogUUID;
    }

    @Override
    public FileChannel open(Path path, OpenOption... options) throws IOException {
        // Create the base FileChannel
        FileChannel baseChannel = FileChannel.open(path, options);

        // Determine if this file should be encrypted
        String fileName = path.getFileName().toString();
        boolean shouldEncrypt = fileName.endsWith(".tlog");

        // CRITICAL DEBUG: Log every channel creation
        logger
            .error(
                "CRYPTO DEBUG: CryptoChannelFactory.open() - path={}, shouldEncrypt={}, options={}",
                path,
                shouldEncrypt,
                Arrays.toString(options)
            );

        if (shouldEncrypt) {
            // Wrap with crypto functionality using unified key resolver and exact UUID
            Set<OpenOption> optionsSet = new HashSet<>(Arrays.asList(options));

            CryptoFileChannelWrapper wrapper = new CryptoFileChannelWrapper(baseChannel, keyIvResolver, path, optionsSet, translogUUID);

            logger.error("CRYPTO DEBUG: Created CryptoFileChannelWrapper for path={}, headerSize={}", path, wrapper.getHeaderSize());

            return wrapper;
        } else {
            logger.error("CRYPTO DEBUG: Using unwrapped channel for path={}", path);
            // Return unwrapped channel for non-encrypted files
            return baseChannel;
        }
    }

    /**
     * Gets the key IV resolver used by this factory.
     *
     * @return the key IV resolver
     */
    public KeyIvResolver getKeyIvResolver() {
        return keyIvResolver;
    }
}
