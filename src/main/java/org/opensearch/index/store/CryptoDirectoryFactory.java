/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.LockFactory;
import org.opensearch.cluster.metadata.CryptoMetadata;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Setting.Property;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.crypto.CryptoHandlerRegistry;
import org.opensearch.index.IndexModule;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.shard.ShardPath;
import org.opensearch.index.store.hybrid.HybridCryptoDirectory;
import org.opensearch.index.store.iv.KeyIvResolver;
import org.opensearch.index.store.mmap.EagerDecryptedCryptoMMapDirectory;
import org.opensearch.index.store.mmap.LazyDecryptedCryptoMMapDirectory;
import org.opensearch.index.store.niofs.CryptoNIOFSDirectory;
import org.opensearch.index.store.systemindex.SystemIndexManager;
import org.opensearch.plugins.IndexStorePlugin;
import org.opensearch.transport.client.Client;

@SuppressForbidden(reason = "temporary")
/**
 * Factory for an encrypted filesystem directory with index-level key management
 */
public class CryptoDirectoryFactory implements IndexStorePlugin.DirectoryFactory {

    private static final Logger LOGGER = LogManager.getLogger(CryptoDirectoryFactory.class);

    private final Supplier<Client> clientSupplier;
    private final Supplier<SystemIndexManager> systemIndexManagerSupplier;
    private final Supplier<CryptoDirectoryPlugin> pluginSupplier;

    /**
     * Creates a new CryptoDirectoryFactory with lazy client, system index manager, and plugin resolution.
     * 
     * @param clientSupplier supplier that provides the client when needed
     * @param systemIndexManagerSupplier supplier that provides the system index manager when needed
     * @param pluginSupplier supplier that provides the plugin instance for shared resolver access
     */
    public CryptoDirectoryFactory(
        Supplier<Client> clientSupplier,
        Supplier<SystemIndexManager> systemIndexManagerSupplier,
        Supplier<CryptoDirectoryPlugin> pluginSupplier
    ) {
        this.clientSupplier = Objects.requireNonNull(clientSupplier, "Client supplier cannot be null");
        this.systemIndexManagerSupplier = Objects
            .requireNonNull(systemIndexManagerSupplier, "System index manager supplier cannot be null");
        this.pluginSupplier = Objects.requireNonNull(pluginSupplier, "Plugin supplier cannot be null");
    }

    /**
     * Gets the client with proper error handling for initialization timing issues.
     * 
     * @return the OpenSearch client
     * @throws IllegalStateException if client is not yet available
     */
    private Client getClient() {
        Client client = clientSupplier.get();
        if (client == null) {
            throw new IllegalStateException(
                "Client not available - OpenSearch may still be initializing. "
                    + "This typically happens during plugin startup. Please ensure the plugin is properly installed "
                    + "and OpenSearch has completed initialization."
            );
        }
        return client;
    }

    /**
     * Gets the system index manager with proper error handling for initialization timing issues.
     * 
     * @return the SystemIndexManager
     * @throws IllegalStateException if system index manager is not yet available
     */
    private SystemIndexManager getSystemIndexManager() {
        SystemIndexManager manager = systemIndexManagerSupplier.get();
        if (manager == null) {
            throw new IllegalStateException(
                "SystemIndexManager not available - OpenSearch may still be initializing. "
                    + "This typically happens during plugin startup. Please ensure the plugin is properly installed "
                    + "and OpenSearch has completed initialization."
            );
        }
        return manager;
    }

    /**
     *  Specifies a crypto provider to be used for encryption. The default value is SunJCE.
     */
    public static final Setting<Provider> INDEX_CRYPTO_PROVIDER_SETTING = new Setting<>("index.store.crypto.provider", "SunJCE", (s) -> {
        Provider p = Security.getProvider(s);
        if (p == null) {
            throw new SettingsException("unrecognized [index.store.crypto.provider] \"" + s + "\"");
        } else
            return p;
    }, Property.IndexScope, Property.InternalIndex);

    /**
     *  Specifies the Key management plugin type to be used. The desired KMS plugin should be installed.
     */
    public static final Setting<String> INDEX_KMS_TYPE_SETTING = new Setting<>("index.store.kms.type", "", Function.identity(), (s) -> {
        if (s == null || s.isEmpty()) {
            throw new SettingsException("index.store.kms.type must be set");
        }
    }, Property.NodeScope, Property.IndexScope);

    /**
     * Specifies the KMS key ID/ARN to use for encrypting data keys for this index.
     */
    public static final Setting<String> INDEX_KMS_KEY_ID_SETTING = new Setting<>("index.store.kms.key_id", "", Function.identity(), (s) -> {
        if (s == null || s.isEmpty()) {
            throw new SettingsException("index.store.kms.key_id must be set");
        }
    }, Property.IndexScope);

    /**
     * Specifies the TTL for data keys in seconds before they are refreshed from KMS. Default is 300 seconds (5 minutes).
     */
    public static final Setting<Integer> KMS_DATA_KEY_TTL_SECONDS_SETTING = Setting
        .intSetting("index.store.kms.data_key_ttl_seconds", 300, 1, Property.NodeScope, Property.IndexScope);

    MasterKeyProvider getKeyProvider(IndexSettings indexSettings) {
        final String KEY_PROVIDER_TYPE = indexSettings.getValue(INDEX_KMS_TYPE_SETTING);
        final Settings settings = Settings.builder().put(indexSettings.getNodeSettings(), false).build();
        CryptoMetadata cryptoMetadata = new CryptoMetadata("", KEY_PROVIDER_TYPE, settings);
        MasterKeyProvider keyProvider;
        try {
            keyProvider = CryptoHandlerRegistry
                .getInstance()
                .getCryptoKeyProviderPlugin(KEY_PROVIDER_TYPE)
                .createKeyProvider(cryptoMetadata);
        } catch (NullPointerException npe) {
            throw new RuntimeException("could not find key provider: " + KEY_PROVIDER_TYPE, npe);
        }
        return keyProvider;
    }

    /**
     * {@inheritDoc}
     * @param indexSettings the index settings
     * @param path the shard file path
     */
    @Override
    public Directory newDirectory(IndexSettings indexSettings, ShardPath path) throws IOException {
        final Path location = path.resolveIndex();
        final LockFactory lockFactory = indexSettings.getValue(org.opensearch.index.store.FsDirectoryFactory.INDEX_LOCK_FACTOR_SETTING);
        Files.createDirectories(location);
        return newFSDirectory(location, lockFactory, indexSettings);
    }

    /**
     * {@inheritDoc}
     * @param location the directory location
     * @param lockFactory the lockfactory for this FS directory
     * @param indexSettings the read index settings 
     * @return the concrete implementation of the directory based on index setttings.
     * @throws IOException
     */
    protected Directory newFSDirectory(Path location, LockFactory lockFactory, IndexSettings indexSettings) throws IOException {
        final Provider provider = indexSettings.getValue(INDEX_CRYPTO_PROVIDER_SETTING);

        MasterKeyProvider keyProvider = getKeyProvider(indexSettings);
        String indexUuid = indexSettings.getIndex().getUUID();

        // Use shared resolver from plugin to ensure consistency with engine operations
        LOGGER.debug("Using shared resolver from plugin for index: {}", indexUuid);
        KeyIvResolver keyIvResolver = pluginSupplier.get().getOrCreateSharedResolver(indexSettings);

        IndexModule.Type type = IndexModule.defaultStoreType(IndexModule.NODE_STORE_ALLOW_MMAP.get(indexSettings.getNodeSettings()));
        Set<String> preLoadExtensions = new HashSet<>(indexSettings.getValue(IndexModule.INDEX_STORE_PRE_LOAD_SETTING));
        // [cfe, tvd, fnm, nvm, write.lock, dii, pay, segments_N, pos, si, fdt, tvx, liv, dvm, fdx, vem]
        Set<String> nioExtensions = new HashSet<>(indexSettings.getValue(IndexModule.INDEX_STORE_HYBRID_NIO_EXTENSIONS));

        switch (type) {
            case HYBRIDFS -> {
                LOGGER.debug("Using HYBRIDFS directory");
                LazyDecryptedCryptoMMapDirectory lazyDecryptedCryptoMMapDirectory = new LazyDecryptedCryptoMMapDirectory(
                    location,
                    provider,
                    keyIvResolver
                );
                EagerDecryptedCryptoMMapDirectory egarDecryptedCryptoMMapDirectory = new EagerDecryptedCryptoMMapDirectory(
                    location,
                    provider,
                    keyIvResolver
                );
                lazyDecryptedCryptoMMapDirectory.setPreloadExtensions(preLoadExtensions);

                return new HybridCryptoDirectory(
                    lockFactory,
                    lazyDecryptedCryptoMMapDirectory,
                    egarDecryptedCryptoMMapDirectory,
                    provider,
                    keyIvResolver,
                    nioExtensions
                );
            }
            case MMAPFS -> {
                LOGGER.debug("Using MMAPFS directory");
                LazyDecryptedCryptoMMapDirectory cryptoMMapDir = new LazyDecryptedCryptoMMapDirectory(location, provider, keyIvResolver);
                cryptoMMapDir.setPreloadExtensions(preLoadExtensions);
                return cryptoMMapDir;
            }
            case SIMPLEFS, NIOFS -> {
                LOGGER.debug("Using NIOFS directory");
                return new CryptoNIOFSDirectory(lockFactory, location, provider, keyIvResolver);
            }
            default -> throw new AssertionError("unexpected built-in store type [" + type + "]");
        }
    }
}
