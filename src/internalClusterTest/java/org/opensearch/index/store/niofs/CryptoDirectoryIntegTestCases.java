/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import java.util.Arrays;
import java.util.Collection;

import static org.hamcrest.Matchers.is;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.index.reindex.ReindexModulePlugin;
import org.opensearch.index.reindex.ReindexRequestBuilder;
import org.opensearch.index.store.CryptoDirectoryPlugin;
import org.opensearch.index.store.MockCryptoKeyProviderPlugin;
import org.opensearch.index.store.MockCryptoPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;


public class CryptoDirectoryIntegTestCases extends OpenSearchIntegTestCase {

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Arrays
            .asList(CryptoDirectoryPlugin.class, MockCryptoKeyProviderPlugin.class, MockCryptoPlugin.class, ReindexModulePlugin.class);
    }

    @Override
    public Settings indexSettings() {
        return Settings
            .builder()
            .put(super.indexSettings())
            .put("index.store.type", "cryptofs")
            .put("index.store.kms.type", "dummy")
            .build();
    }

    // public void testEmptyStoreTypeSettings() {
    // Settings settings = Settings
    // .builder()
    // .put(super.indexSettings())
    // .put("index.store.type", "cryptofs")
    // .put(SETTING_NUMBER_OF_SHARDS, 1)
    // .put(SETTING_NUMBER_OF_REPLICAS, 0)
    // .build();

    // boolean exceptionThrown = false;

    // try {
    // createIndex("test", settings);
    // long nbDocs = randomIntBetween(10, 1000);
    // for (long i = 0; i < nbDocs; i++) {
    // index("test", "doc", "" + i, "foo", "bar");
    // }
    // } catch (Exception e) {
    // exceptionThrown = true;
    // assertTrue("Expected exception type mismatch", e instanceof Exception);
    // }

    // assertTrue("Expected exception was not thrown", exceptionThrown);
    // }

    // public void testUnavailableStoreType() {
    // Settings settings = Settings
    // .builder()
    // .put(super.indexSettings())
    // .put("index.store.type", "cryptofs")
    // .put("index.store.kms.type", "unavailable")
    // .put(SETTING_NUMBER_OF_SHARDS, 1)
    // .put(SETTING_NUMBER_OF_REPLICAS, 0)
    // .build();
    // // Create an index and index some documents
    // createIndex("test", settings);
    // long nbDocs = randomIntBetween(10, 1000);
    // final Exception e = expectThrows(Exception.class, () -> {
    // for (long i = 0; i < nbDocs; i++) {
    // index("test", "doc", "" + i, "foo", "bar");
    // }
    // });
    // assertTrue(e instanceof Exception);
    // }
    public void testReindex() {
        // Create an index and index some documents
        createIndex("test");
        createIndex("test_copy");
        long nbDocs = randomIntBetween(10, 1000);
        for (long i = 0; i < nbDocs; i++) {
            index("test", "doc", "" + i, "foo", "bar");
        }
        refresh();
        SearchResponse response = client().prepareSearch("test").get();
        assertThat(response.getHits().getTotalHits().value(), is(nbDocs));

        // Reindex
        reindex().source("test").destination("test_copy").refresh(true).get();
        SearchResponse copy_response = client().prepareSearch("test_copy").get();
        assertThat(copy_response.getHits().getTotalHits().value(), is(nbDocs));

    }

    public void testDelete() {
        // Create an index and index some documents
        createIndex("todelete");
        long nbDocs = randomIntBetween(10, 1000);
        for (long i = 0; i < nbDocs; i++) {
            index("todelete", "doc", "" + i, "foo", "bar");
        }
        refresh();
        SearchResponse response = client().prepareSearch("todelete").get();
        assertThat(response.getHits().getTotalHits().value(), is(nbDocs));

        // Deleteindex
        DeleteIndexRequest deleteIndexRequest = new DeleteIndexRequest("todelete");
        client().admin().indices().delete(deleteIndexRequest).actionGet();

        final IndexNotFoundException e = expectThrows(IndexNotFoundException.class, () -> client().prepareSearch("todelete").get());
        assertTrue(e.getMessage().contains("no such index"));
    }

    ReindexRequestBuilder reindex() {
        return new ReindexRequestBuilder(client(), ReindexAction.INSTANCE);
    }
}
