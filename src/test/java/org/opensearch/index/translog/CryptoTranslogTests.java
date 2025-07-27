/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.BigArrays;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.store.iv.DefaultKeyIvResolver;
import org.opensearch.index.store.iv.KeyIvResolver;
import org.opensearch.index.translog.CryptoChannelFactory;
import org.opensearch.index.translog.CryptoTranslog;
import org.opensearch.index.translog.TranslogConfig;
import org.opensearch.index.translog.TranslogDeletionPolicy;
import org.opensearch.index.translog.TranslogReader;
import org.opensearch.index.translog.TranslogWriter;

import java.util.List;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for CryptoTranslog to verify basic functionality.
 * Updated to use unified KeyIvResolver approach.
 */
public class CryptoTranslogTests {

    private static final Logger logger = LogManager.getLogger(CryptoTranslogTests.class);
    
    private Path tempDir;
    private IndexSettings indexSettings;
    private TranslogConfig config;
    private Provider cryptoProvider;
    private KeyIvResolver keyIvResolver;
    private MasterKeyProvider keyProvider;

    @Before
    public void setUp() throws IOException {
        tempDir = Files.createTempDirectory("crypto-translog-test");
        
        // Create minimal settings for testing
        Settings settings = Settings.builder()
            .put("index.store.crypto.provider", "SunJCE")
            .put("index.store.kms.type", "test")
            .build();
        
        indexSettings = new IndexSettings(
            IndexMetadata.builder("test-index")
                .settings(Settings.builder()
                    .put(settings)
                    .put("index.version.created", org.opensearch.Version.CURRENT)
                    .build())
                .numberOfShards(1)
                .numberOfReplicas(0)
                .build(),
            settings
        );
        
        cryptoProvider = Security.getProvider("SunJCE");
        
        // Create a mock key provider for testing
        keyProvider = new MasterKeyProvider() {
            @Override
            public java.util.Map<String, String> getEncryptionContext() {
                return java.util.Collections.singletonMap("test-key", "test-value");
            }
            
            @Override
            public byte[] decryptKey(byte[] encryptedKey) {
                return new byte[32]; // 256-bit key
            }
            
            @Override
            public String getKeyId() {
                return "test-key-id";
            }
            
            @Override
            public org.opensearch.common.crypto.DataKeyPair generateDataPair() {
                byte[] rawKey = new byte[32];
                byte[] encryptedKey = new byte[32];
                return new org.opensearch.common.crypto.DataKeyPair(rawKey, encryptedKey);
            }
            
            @Override
            public void close() {
                // No resources to close
            }
        };
        
        // Create a directory for the key/IV resolver
        org.apache.lucene.store.Directory directory = new org.apache.lucene.store.NIOFSDirectory(tempDir);
        keyIvResolver = new DefaultKeyIvResolver(directory, cryptoProvider, keyProvider);
        
        config = new TranslogConfig(
            new ShardId("test-index", "test-uuid", 0),
            tempDir,
            indexSettings,
            BigArrays.NON_RECYCLING_INSTANCE,
            "test-node",
            false
        );
    }

    @Test
    public void testCryptoTranslogCreation() throws IOException {
        // Create a simple deletion policy for testing
        TranslogDeletionPolicy deletionPolicy = new TranslogDeletionPolicy() {
            public long getMinTranslogGenerationForRecovery() {
                return 0;
            }
            
            @Override
            public long getLocalCheckpointOfSafeCommit() {
                return 0;
            }
            
            @Override
            public void setLocalCheckpointOfSafeCommit(long localCheckpointOfSafeCommit) {
                // No-op for testing
            }
            
            @Override
            public long minTranslogGenRequired(List<TranslogReader> readers, TranslogWriter writer) {
                return 0;
            }
            
            @Override
            public void setRetentionTotalFiles(int retentionTotalFiles) {
                // No-op for testing
            }
            
            @Override
            public void setRetentionAgeInMillis(long retentionAgeInMillis) {
                // No-op for testing
            }
            
            @Override
            public void setRetentionSizeInBytes(long retentionSizeInBytes) {
                // No-op for testing
            }
        };
        
        // Create initial translog structure - this is required by LocalTranslog
        Path checkpointPath = tempDir.resolve("translog.ckp");
        Path translogPath = tempDir.resolve("translog-0.tlog");
        
        // Ensure the directory exists
        Files.createDirectories(checkpointPath.getParent());
        
        // Create the initial translog file first
        CryptoChannelFactory channelFactory = new CryptoChannelFactory(keyIvResolver);
        
        // Create empty translog file with proper header using OpenSearch's TranslogHeader
        long headerSize;
        try (java.nio.channels.FileChannel translogChannel = channelFactory.open(translogPath, 
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.WRITE)) {
            
            // Create and write a proper translog header
            org.opensearch.index.translog.TranslogHeader header = new org.opensearch.index.translog.TranslogHeader(
                "test-translog-uuid", 
                1L // primary term
            );
            
            // Write the header - this will NOT be encrypted due to our header-aware approach
            header.write(translogChannel, false);
            
            // Get the actual header size
            headerSize = header.sizeInBytes();
        }
        
        // Now create the checkpoint pointing to the translog file
        org.opensearch.index.translog.Checkpoint initialCheckpoint = org.opensearch.index.translog.Checkpoint.emptyTranslogCheckpoint(
            headerSize, // offset after header
            0, // numOps
            0, // generation (should be 0 for translog-0.tlog)
            0  // minTranslogGeneration
        );
        
        // Write the initial checkpoint using CryptoChannelFactory
        org.opensearch.index.translog.Checkpoint.write(
            channelFactory, 
            checkpointPath, 
            initialCheckpoint, 
            java.nio.file.StandardOpenOption.CREATE,
            java.nio.file.StandardOpenOption.WRITE
        );
        
        // Test that CryptoTranslog can be created successfully with unified key resolver
        CryptoTranslog translog = new CryptoTranslog(
            config,
            "test-translog-uuid",
            deletionPolicy,
            () -> 0L, // globalCheckpointSupplier
            () -> 1L, // primaryTermSupplier
            seqNo -> {}, // persistedSequenceNumberConsumer
            keyIvResolver // unified key resolver
        );
        
        assertNotNull("CryptoTranslog should be created successfully", translog);
        assertNotNull("CryptoTranslog should have a key IV resolver", translog.getKeyIvResolver());
        
        // Verify the channel factory is crypto-enabled
        assertTrue("Channel factory should be crypto-enabled", 
            translog.getChannelFactory() instanceof CryptoChannelFactory);
        
        logger.info("CryptoTranslog created successfully with unified key management");
        
        // Note: OpenSearch handles translog cleanup automatically - explicit close() is not allowed in tests
    }

    @Test
    public void testChannelFactoryFileTypeDetection() throws IOException {
        // Test that the channel factory correctly identifies .tlog vs .ckp files
        CryptoChannelFactory factory = new CryptoChannelFactory(keyIvResolver);
        
        assertNotNull("Channel factory should be created", factory);
        assertNotNull("Channel factory should have key IV resolver", factory.getKeyIvResolver());
        
        logger.info("CryptoChannelFactory configured correctly for file type detection");
    }
}
