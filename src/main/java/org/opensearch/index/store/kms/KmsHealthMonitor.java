/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.kms;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.lifecycle.AbstractLifecycleComponent;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.store.iv.DefaultKeyIvResolver;
import org.opensearch.threadpool.Scheduler;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

/**
 * Node-level service that monitors KMS health and orchestrates recovery of failed resolvers.
 * This component tracks DefaultKeyIvResolver instances that have encountered non-retryable KMS failures
 * and periodically tests KMS connectivity to detect recovery.
 * 
 * When KMS service recovery is detected, it:
 * 1. Resets circuit breakers on all failed resolvers
 * 2. Triggers cluster reroute to redistribute failed shards
 * 3. Stops monitoring until new failures occur
 * 
 * @opensearch.internal
 */
public class KmsHealthMonitor extends AbstractLifecycleComponent {

    private static final Logger logger = LogManager.getLogger(KmsHealthMonitor.class);

    // Static registry for node-level access
    private static volatile KmsHealthMonitor instance;
    private static final Object instanceLock = new Object();

    private final Set<DefaultKeyIvResolver> failedResolvers = ConcurrentHashMap.newKeySet();
    private final ThreadPool threadPool;
    private final Client client;
    private final ClusterService clusterService;

    // Monitoring configuration - reuse TTL setting for interval
    private volatile TimeValue monitoringInterval;
    private volatile Scheduler.Cancellable monitoringTask;

    // Metrics
    private volatile long totalFailedResolvers = 0;
    private volatile long successfulRecoveries = 0;
    private volatile long lastRecoveryTime = 0;

    private KmsHealthMonitor(Settings settings, ThreadPool threadPool, Client client, ClusterService clusterService) {
        this.threadPool = threadPool;
        this.client = client;
        this.clusterService = clusterService;

        // Use node-level TTL setting as monitoring interval
        int defaultTtlSeconds = settings.getAsInt("index.store.kms.data_key_ttl_seconds", 120);
        this.monitoringInterval = TimeValue.timeValueSeconds(defaultTtlSeconds);

        logger.info("KMS Health Monitor initialized with interval: {} (from node-level TTL setting)", monitoringInterval);
    }

    /**
     * Registers a resolver that has encountered a non-retryable KMS failure.
     * Starts monitoring if this is the first failed resolver.
     * 
     * @param resolver the resolver with circuit breaker activated
     * @param failureType the type of non-retryable failure that occurred
     */
    public void registerFailedResolver(DefaultKeyIvResolver resolver, KmsFailureType failureType) {
        boolean wasEmpty = failedResolvers.isEmpty();
        failedResolvers.add(resolver);
        totalFailedResolvers++;

        logger
            .warn(
                "Registered resolver for KMS health monitoring due to {} failure. " + "Total failed resolvers: {}, Monitoring interval: {}",
                failureType,
                failedResolvers.size(),
                monitoringInterval
            );

        if (wasEmpty && lifecycle.started()) {
            startMonitoring();
        }
    }

    /**
     * Removes a resolver from monitoring (e.g., when index is deleted).
     * 
     * @param resolver the resolver to stop monitoring
     */
    public void unregisterResolver(DefaultKeyIvResolver resolver) {
        if (failedResolvers.remove(resolver)) {
            logger.info("Unregistered resolver from KMS health monitoring. Remaining failed resolvers: {}", failedResolvers.size());

            if (failedResolvers.isEmpty()) {
                stopMonitoring();
            }
        }
    }

    /**
     * Starts the periodic monitoring task.
     */
    private void startMonitoring() {
        if (monitoringTask != null) {
            return; // Already monitoring
        }

        monitoringTask = threadPool.scheduleWithFixedDelay(this::checkKmsHealth, monitoringInterval, ThreadPool.Names.GENERIC);

        logger.info("Started KMS health monitoring with {} failed resolvers", failedResolvers.size());
    }

    /**
     * Stops the periodic monitoring task.
     */
    private void stopMonitoring() {
        if (monitoringTask != null) {
            monitoringTask.cancel();
            monitoringTask = null;
            logger.info("Stopped KMS health monitoring - no failed resolvers remaining");
        }
    }

    /**
     * Periodic health check that tests KMS connectivity and triggers recovery if available.
     */
    private void checkKmsHealth() {
        if (failedResolvers.isEmpty()) {
            stopMonitoring();
            return;
        }

        logger.debug("Checking KMS health for {} failed resolvers", failedResolvers.size());

        // Test connectivity using one representative resolver
        DefaultKeyIvResolver testResolver = failedResolvers.iterator().next();

        if (testKmsConnectivity(testResolver)) {
            handleKmsRecovery();
        } else {
            logger.debug("KMS still unavailable, continuing monitoring");
        }
    }

    /**
     * Tests KMS connectivity by attempting a key refresh operation.
     * 
     * @param resolver resolver to test with
     * @return true if KMS is accessible, false otherwise
     */
    private boolean testKmsConnectivity(DefaultKeyIvResolver resolver) {
        try {
            // Attempt to test KMS connectivity
            // This would call a method on the resolver to test KMS without affecting normal operations
            resolver.testKmsConnectivity();
            logger.debug("KMS connectivity test successful");
            return true;
        } catch (Exception e) {
            KmsFailureType failureType = KmsFailureClassifier.classify(e);

            if (KmsFailureClassifier.isRetryable(failureType)) {
                // If failure is now retryable, KMS might be recovering
                logger.info("KMS failure type changed to retryable: {}", failureType);
                return true;
            } else {
                logger.debug("KMS connectivity test failed: {} ({})", failureType, e.getMessage());
                return false;
            }
        }
    }

    /**
     * Handles KMS recovery by resetting circuit breakers and triggering cluster recovery.
     */
    private void handleKmsRecovery() {
        int resolverCount = failedResolvers.size();

        logger.info("KMS recovery detected! Resetting {} circuit breakers and triggering cluster reroute.", resolverCount);

        // Reset all circuit breakers
        failedResolvers.forEach(resolver -> resolver.resetCircuitBreaker());
        failedResolvers.clear();

        // Update metrics
        successfulRecoveries++;
        lastRecoveryTime = System.currentTimeMillis();

        // Trigger cluster reroute for failed shards
        triggerClusterRecovery();

        stopMonitoring();
    }

    /**
     * Triggers cluster reroute to redistribute shards that may have failed due to KMS issues.
     */
    private void triggerClusterRecovery() {
        try {
            client.admin().cluster().prepareReroute().setRetryFailed(true).execute(ActionListener.wrap(response -> {
                logger.info("Automatic cluster reroute completed successfully after KMS recovery");
            }, failure -> { logger.warn("Automatic cluster reroute failed after KMS recovery: {}", failure.getMessage()); }));
        } catch (Exception e) {
            logger.warn("Failed to trigger automatic cluster reroute after KMS recovery: {}", e.getMessage());
        }
    }

    /**
     * Gets monitoring status and metrics.
     * 
     * @return formatted status string
     */
    public String getMonitoringStatus() {
        return String
            .format(
                "KMS Monitor: Active=%s, FailedResolvers=%d, TotalFailed=%d, Recoveries=%d, LastRecovery=%s",
                isMonitoring(),
                failedResolvers.size(),
                totalFailedResolvers,
                successfulRecoveries,
                lastRecoveryTime > 0 ? new java.util.Date(lastRecoveryTime).toString() : "Never"
            );
    }

    /**
     * Checks if monitoring is currently active.
     * 
     * @return true if monitoring task is running
     */
    public boolean isMonitoring() {
        return monitoringTask != null && !monitoringTask.isCancelled();
    }

    /**
     * Gets the current number of failed resolvers being monitored.
     * 
     * @return number of failed resolvers
     */
    public int getFailedResolverCount() {
        return failedResolvers.size();
    }

    @Override
    protected void doStart() {
        logger.info("KMS Health Monitor service started");

        // Start monitoring if there are already failed resolvers
        if (!failedResolvers.isEmpty()) {
            startMonitoring();
        }
    }

    @Override
    protected void doStop() {
        stopMonitoring();
        logger.info("KMS Health Monitor service stopped");
    }

    @Override
    protected void doClose() {
        stopMonitoring();
        failedResolvers.clear();
        logger.info("KMS Health Monitor service closed");
    }

    /**
     * Initializes the singleton instance of KmsHealthMonitor.
     * This should be called once during node startup.
     * 
     * @param settings node settings
     * @param threadPool thread pool for scheduling tasks
     * @param client client for cluster operations
     * @param clusterService cluster service
     */
    public static void initialize(Settings settings, ThreadPool threadPool, Client client, ClusterService clusterService) {
        if (instance == null) {
            synchronized (instanceLock) {
                if (instance == null) {
                    instance = new KmsHealthMonitor(settings, threadPool, client, clusterService);
                    instance.start();
                    logger.info("KMS Health Monitor singleton initialized");
                }
            }
        }
    }

    /**
     * Gets the singleton instance of KmsHealthMonitor.
     * Returns null if not initialized.
     * 
     * @return the health monitor instance, or null if not initialized
     */
    public static KmsHealthMonitor getInstance() {
        return instance;
    }

    /**
     * Safely registers a resolver with the health monitor.
     * Does nothing if the health monitor is not initialized.
     * 
     * @param resolver the resolver to register
     * @param failureType the failure type that occurred
     */
    public static void safeRegisterFailedResolver(DefaultKeyIvResolver resolver, KmsFailureType failureType) {
        KmsHealthMonitor monitor = getInstance();
        if (monitor != null) {
            monitor.registerFailedResolver(resolver, failureType);
        } else {
            logger.warn("KMS Health Monitor not initialized - cannot register failed resolver");
        }
    }
}
