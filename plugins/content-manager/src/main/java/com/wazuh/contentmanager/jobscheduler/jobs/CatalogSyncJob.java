package com.wazuh.contentmanager.jobscheduler.jobs;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerService;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SnapshotServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.UpdateServiceImpl;
import com.wazuh.contentmanager.jobscheduler.JobExecutor;
import com.wazuh.securityanalytics.action.*;
import com.wazuh.securityanalytics.model.Integration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.env.Environment;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import static org.opensearch.rest.RestRequest.Method.POST;


/**
 * Job responsible for executing the synchronization logic for Rules and Decoders consumers.
 */
public class CatalogSyncJob implements JobExecutor {
    private static final Logger log = LogManager.getLogger(CatalogSyncJob.class);

    // Identifier used to route this specific job type
    public static final String JOB_TYPE = "consumer-sync-task";
    public static final String DECODERS = "decoders";
    public static final String KVDBS = "kvdbs";
    public static final String RULES = "rules";
    public static final String INTEGRATIONS = "integrations";
    public static final String DOCUMENT = "document";
    public static final String POLICY = "policy";
    public static final String SPACE = "space";
    public static final String RULE = "rule";
    public static final String KVDB = "kvdb";
    public static final String DECODER = "decoder";
    public static final String INTEGRATION = "integration";
    static final String CATEGORY = "category";

    // Semaphore to control concurrency
    private final Semaphore semaphore = new Semaphore(1);

    private final Client client;
    private final ConsumersIndex consumersIndex;
    private final Environment environment;
    private final ThreadPool threadPool;

    /**
     * Constructs a new CatalogSyncJob.
     *
     * @param client         The OpenSearch client used for administrative index operations (create/check).
     * @param consumersIndex The wrapper for accessing and managing the internal Consumers index.
     * @param environment    The OpenSearch environment settings, used for path resolution.
     * @param threadPool     The thread pool manager, used to offload blocking tasks to the generic executor.
     */
    public CatalogSyncJob(Client client, ConsumersIndex consumersIndex, Environment environment, ThreadPool threadPool) {
        this.client = client;
        this.consumersIndex = consumersIndex;
        this.environment = environment;
        this.threadPool = threadPool;
    }

    /**
     * Triggers the execution of the synchronization job via the Job Scheduler.
     *
     * @param context The execution context provided by the Job Scheduler, containing metadata like the Job ID.
     */
    @Override
    public void execute(JobExecutionContext context) {
        if (!this.semaphore.tryAcquire()) {
            log.warn("CatalogSyncJob (ID: {}) skipped because synchronization is already running.", context.getJobId());
            return;
        }

        // Offload execution to the generic thread pool to allow blocking operations
        this.threadPool.generic().execute(() -> {
            try {
                log.info("Executing Consumer Sync Job (ID: {})", context.getJobId());
                this.performSynchronization();
            } catch (Exception e) {
                log.error("Error executing Consumer Sync Job (ID: {}): {}", context.getJobId(), e.getMessage(), e);
            } finally {
                this.semaphore.release();
            }
        });
    }

    /**
     * Checks if the synchronization job is currently running.
     *
     * @return true if running, false otherwise.
     */
    public boolean isRunning() {
        return this.semaphore.availablePermits() == 0;
    }

    /**
     * Attempts to trigger the synchronization process manually.
     */
    public void trigger() {
        if (!this.semaphore.tryAcquire()) {
            log.warn("Attempted to trigger CatalogSyncJob manually while it is already running.");
            return;
        }
        this.threadPool.generic().execute(() -> {
            try {
                log.info("Executing Manually Triggered Consumer Sync Job");
                this.performSynchronization();
            } catch (Exception e) {
                log.error("Error executing Manual Consumer Sync Job: {}", e.getMessage(), e);
            } finally {
                this.semaphore.release();
            }
        });

    }

    /**
     * Centralized synchronization logic used by both execute() and trigger().
     */
    private void performSynchronization() {
        this.rulesConsumer();
        this.decodersConsumer();
    }

    /**
     * Orchestrates the synchronization process specifically for the Rules consumer.
     */
    private void rulesConsumer() {
        String context = "rules_development_0.0.1";
        String consumer = "rules_development_0.0.1_test";

        Map<String, String> mappings = new HashMap<>();
        mappings.put(
            RULE, "/mappings/cti-rules-mappings.json"
        );
        mappings.put(
            INTEGRATION, "/mappings/cti-rules-integrations-mappings.json"
        );

        Map<String, String> aliases = new HashMap<>();
        aliases.put(RULE, ".cti-rules");
        aliases.put(INTEGRATION, ".cti-integration-rules");

        boolean isUpdated = this.syncConsumerServices(context, consumer, mappings, aliases);
        log.info("Rules Consumer correctly synchronized.");

        if (isUpdated) {
            try {
                this.client.admin().indices().prepareRefresh(
                    this.getIndexName(context, consumer, "rule"),
                    this.getIndexName(context, consumer, "integration")
                ).get();
            } catch (Exception e) {
                log.warn("Error refreshing indices before sending them to SAP: {}", e.getMessage());
            }

            String integrationIndex = this.getIndexName(context, consumer, "integration");
            String ruleIndex = this.getIndexName(context, consumer, "rule");

            Map<String, List<String>> integrations = this.processIntegrations(integrationIndex);
            this.processRules(ruleIndex);
            this.createOrUpdateDetectors(integrations, integrationIndex);
        }
    }

    private void createOrUpdateDetectors(Map<String, List<String>> integrations, String indexName) {
        log.info("Creating detectors for integrations... : {}", integrations.keySet());
        try {
            if (!this.client.admin().indices().prepareExists(indexName).get().isExists()) {
                log.warn("Integration index [{}] does not exist, skipping treat detectors sync.", indexName);
            }

            SearchRequest searchRequest = new SearchRequest(indexName);
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(QueryBuilders.matchAllQuery());
            searchSourceBuilder.size(10000);
            searchRequest.source(searchSourceBuilder);

            SearchResponse searchResponse = this.client.search(searchRequest).actionGet();
            for (SearchHit hit : searchResponse.getHits().getHits()) {
                try {
                    JsonObject source = JsonParser.parseString(hit.getSourceAsString()).getAsJsonObject();
                    if (source.has("document")) {
                        JsonObject doc = source.getAsJsonObject("document");
                        String name = doc.has("title") ? doc.get("title").getAsString() : "";
                        String category = this.getCategory(doc);
                        List<String> rules = new ArrayList<>();
                        if (doc.has("rules")) {
                            doc.get("rules").getAsJsonArray().forEach(item -> rules.add(item.getAsString()));
                        }

                        WIndexDetectorRequest request = new WIndexDetectorRequest(
                            name,
                            category,
                            rules,
                            WriteRequest.RefreshPolicy.IMMEDIATE);
                        this.client.execute(WIndexDetectorAction.INSTANCE, request).get(1, TimeUnit.SECONDS);
                        log.info("Detector [{}] synced successfully.", name);
                    }
                } catch (Exception e) {
                    log.error("Failed to sync Threat Detector from hit [{}]: {}", hit.getId(), e.getMessage());
                }
            }
        } catch (Exception e) {
            log.error("Error reading integrations from index [{}]: {}", indexName, e.getMessage());
        }
    }

    public String getCategory(JsonObject doc) {
        String rawCategory = doc.get(CATEGORY).getAsString();

        // TODO remove when CTI applies the changes to the categorization.
        // Remove subcategory. Currently only cloud-services has subcategories (aws, gcp, azure).
        if (rawCategory.contains("cloud-services")) {
            rawCategory = rawCategory.substring(0, 14);
        }
        return Arrays.stream(
            rawCategory
                .split("-"))
                .reduce("", (current, next) -> current + " " + Strings.capitalize(next))
                .trim();
    }

    private Map<String, List<String>> processIntegrations(String indexName) {
        Map<String, List<String>> integrations = new HashMap<>();
        try {
            if (!this.client.admin().indices().prepareExists(indexName).get().isExists()) {
                log.warn("Integration index [{}] does not exist, skipping integration sync.", indexName);
                return integrations;
            }

            SearchRequest searchRequest = new SearchRequest(indexName);
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(QueryBuilders.matchAllQuery());
            searchSourceBuilder.size(10000);
            searchRequest.source(searchSourceBuilder);

            SearchResponse searchResponse = this.client.search(searchRequest).actionGet();

            for (SearchHit hit : searchResponse.getHits().getHits()) {
                try {
                    JsonObject source = JsonParser.parseString(hit.getSourceAsString()).getAsJsonObject();
                    if (source.has("document")) {
                        JsonObject doc = source.getAsJsonObject("document");
                        String id = doc.get("id").getAsString();
                        String name = doc.has("title") ? doc.get("title").getAsString() : "";
                        String description = doc.has("description") ? doc.get("description").getAsString() : "";
                        String category = this.getCategory(doc);
                        List<String> rules = new ArrayList<>();
                        if (doc.has("rules")) {
                            doc.get("rules").getAsJsonArray().forEach(item -> rules.add(item.getAsString()));
                        }
                        if (rules.isEmpty()) {
                            continue;
                        }
                        WIndexIntegrationRequest request = new WIndexIntegrationRequest(
                            id,
                            WriteRequest.RefreshPolicy.IMMEDIATE,
                            POST,
                            new Integration(
                                id,
                                null,
                                name,
                                description,
                                category,
                                "Sigma",
                                rules,
                                new HashMap<>()
                            )
                        );

                        WIndexIntegrationResponse response = this.client.execute(WIndexIntegrationAction.INSTANCE, request).get(1, TimeUnit.SECONDS);
                        log.info("Integration [{}] synced successfully. Response ID: {}", id, response.getId());
                        integrations.put(name, rules);
                    }
                } catch (Exception e) {
                    log.error("Failed to sync integration from hit [{}]: {} {}", hit.getId(), e.getMessage(), e);
                }
            }
        } catch (Exception e) {
            log.error("Error processing integrations from index [{}]: {}", indexName, e.getMessage());
        }
        return integrations;
    }

    private void processRules(String indexName) {
        try {
            if (!this.client.admin().indices().prepareExists(indexName).get().isExists()) {
                log.warn("Rule index [{}] does not exist, skipping rule sync.", indexName);
                return;
            }

            SearchRequest searchRequest = new SearchRequest(indexName);
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(QueryBuilders.matchAllQuery());
            searchSourceBuilder.size(10000);
            searchRequest.source(searchSourceBuilder);

            SearchResponse searchResponse = this.client.search(searchRequest).actionGet();

            for (SearchHit hit : searchResponse.getHits().getHits()) {
                try {
                    JsonObject source = JsonParser.parseString(hit.getSourceAsString()).getAsJsonObject();

                    if (source.has("document")) {
                        // Extract the actual rule content
                        JsonObject doc = source.getAsJsonObject("document");

                        String id = doc.get("id").getAsString();

                        // Determine product for the rule request
                        String product = "linux"; // Default
                        if (doc.has("logsource")) {
                            JsonObject logsource = doc.getAsJsonObject("logsource");
                            if (logsource.has("product")) {
                                product = logsource.get("product").getAsString();
                            } else if (logsource.has(CATEGORY)) {
                                product = logsource.get(CATEGORY).getAsString();
                            }
                        }

                        WIndexRuleRequest ruleRequest = new WIndexRuleRequest(
                            id,
                            WriteRequest.RefreshPolicy.IMMEDIATE,
                            product,
                            POST,
                            doc.toString(),
                            false
                        );

                        WIndexRuleResponse response = this.client.execute(WIndexRuleAction.INSTANCE, ruleRequest).get(1, TimeUnit.SECONDS);
                        log.info("Rule [{}] synced successfully. Response ID: {}", id, response.getId());
                    }
                } catch (Exception e) {
                    log.error("Failed to sync rule from hit [{}]: {}", hit.getId(), e.getMessage());
                }
            }
        } catch (Exception e) {
            log.error("Error processing rules from index [{}]: {}", indexName, e.getMessage());
        }
    }

    /**
     * Orchestrates the synchronization process specifically for the Decoders consumer.
     */
    private void decodersConsumer() {
        String context = "decoders_development_0.0.1";
        String consumer = "decoders_development_0.0.1";

        Map<String, String> mappings = new HashMap<>();
        mappings.put(
            DECODER, "/mappings/cti-decoders-mappings.json"
        );
        mappings.put(
            KVDB, "/mappings/cti-kvdbs-mappings.json"
        );
        mappings.put(
            INTEGRATION, "/mappings/cti-decoders-integrations-mappings.json"
        );
        mappings.put(
            POLICY, "/mappings/cti-policies-mappings.json"
        );

        Map<String, String> aliases = new HashMap<>();
        aliases.put(DECODER, ".cti-decoders");
        aliases.put(KVDB, ".cti-kvdbs");
        aliases.put(INTEGRATION, ".cti-integration-decoders");
        aliases.put(POLICY, ".cti-policies");

        boolean isConsumerUpdated = this.syncConsumerServices(context, consumer, mappings, aliases);

        // Only calculate hashes if there was an update
        if (isConsumerUpdated) {
            log.info("Changes detected in Decoders Consumer. Refreshing indices and calculating hashes...");
            try {
                this.client.admin().indices().prepareRefresh(
                    this.getIndexName(context, consumer, DECODER),
                    this.getIndexName(context, consumer, KVDB),
                    this.getIndexName(context, consumer, INTEGRATION),
                    this.getIndexName(context, consumer, POLICY)
                ).get();
            } catch (Exception e) {
                log.warn("Error refreshing indices before hash calculation: {}", e.getMessage());
            }

            // Calculate and update hash of hashes
            this.hashPolicy(context, consumer);
        } else {
            log.info("No changes in Decoders Consumer. Skipping hash calculation.");
        }

        log.info("Decoders Consumer correctly synchronized.");
    }

    /**
     * Generates a standardized OpenSearch index name based on the provided parameters.
     *
     * @param context  The context identifier (e.g., version info).
     * @param consumer The consumer identifier.
     * @param type     The specific content type (e.g., "rule", "decoder").
     * @return A formatted string representing the system index name.
     */
    private String getIndexName(String context, String consumer, String type) {
        return String.format(
            Locale.ROOT, ".%s-%s-%s",
            context,
            consumer,
            type
        );
    }

    /**
     * The core logic for synchronizing consumer services.
     * <p>
     * This method performs the following actions:
     * 1. Retrieve the Local and Remote consumer metadata.
     * 2. Iterate through the requested mappings to check if indices exist.
     * 3. Create indices using the provided mapping files if they are missing.
     * 4. Compare local offsets with remote offsets to determine if a Snapshot initialization is required.
     * 5. Triggers a full snapshot download if the local consumer is new or empty.
     * 6. Triggers the update process if the offsets from local and remote consumers differ.
     *
     * @param context  The versioned context string.
     * @param consumer The specific consumer identifier.
     * @param mappings A map associating content types to their JSON mapping file paths.
     * @param aliases  A map associating content types to their OpenSearch alias names.
     * @return true if an update or initialization occurred, false otherwise.
     */
    private boolean syncConsumerServices(String context, String consumer, Map<String, String> mappings, Map<String, String> aliases) {
        ConsumerService consumerService = new ConsumerServiceImpl(context, consumer, this.consumersIndex);
        LocalConsumer localConsumer = consumerService.getLocalConsumer();
        RemoteConsumer remoteConsumer = consumerService.getRemoteConsumer();

        List<ContentIndex> indices = new ArrayList<>();
        Map<String, ContentIndex> indicesMap = new HashMap<>();

        for (Map.Entry<String, String> entry : mappings.entrySet()) {
            String indexName = this.getIndexName(context, consumer, entry.getKey());
            String alias = aliases.get(entry.getKey());
            ContentIndex index = new ContentIndex(this.client, indexName, entry.getValue(), alias);
            indices.add(index);
            indicesMap.put(entry.getKey(), index);

            // Check if index exists to avoid creation exception
            boolean indexExists = this.client.admin().indices().prepareExists(indexName).get().isExists();

            if (!indexExists) {
                try {
                    CreateIndexResponse response = index.createIndex();
                    if (response.isAcknowledged()) {
                        log.info("Index [{}] created successfully", response.index());
                    }
                } catch (Exception e) {
                    log.error("Failed to create index [{}]: {}", indexName, e.getMessage());
                }
            }
        }

        boolean updated = false;
        long currentOffset = localConsumer != null ? localConsumer.getLocalOffset() : 0;

        // Snapshot Initialization
        if (remoteConsumer != null && remoteConsumer.getSnapshotLink() != null && currentOffset == 0) {
            log.info("Initializing snapshot from link: {}", remoteConsumer.getSnapshotLink());
            SnapshotServiceImpl snapshotService = new SnapshotServiceImpl(
                context,
                consumer,
                indices,
                this.consumersIndex,
                this.environment
            );
            snapshotService.initialize(remoteConsumer);

            currentOffset = remoteConsumer.getSnapshotOffset();
            updated = true;
        }

        // Update
        if (remoteConsumer != null && currentOffset < remoteConsumer.getOffset()) {
            log.info("Performing update for consumer [{}] from offset [{}] to [{}]", consumer, currentOffset, remoteConsumer.getOffset());

            UpdateServiceImpl updateService = new UpdateServiceImpl(
                context,
                consumer,
                new ApiClient(),
                this.consumersIndex,
                indicesMap
            );
            updateService.update(currentOffset, remoteConsumer.getOffset());
            updateService.close();
            updated = true;
        }
        return updated;
    }

    /**
     * Calculates the aggregate hash (hash of hashes) and update the policies.
     */
    private void hashPolicy(String context, String consumer) {
        try {
            // Space hash is generated in this order
            String policyIndex = this.getIndexName(context, consumer, POLICY);
            String integrationIndex = this.getIndexName(context, consumer, INTEGRATION);
            String decoderIndex = this.getIndexName(context, consumer, DECODER);
            String kvdbIndex = this.getIndexName(context, consumer, KVDB);
            String ruleIndex = this.getIndexName(context, consumer, RULE);

            // Verify policy index exists
            if (!this.client.admin().indices().prepareExists(policyIndex).get().isExists()) {
                log.warn("Policy index [{}] does not exist. Skipping hash calculation.", policyIndex);
                return;
            }

            // Fetch all policies
            SearchRequest searchRequest = new SearchRequest(policyIndex);
            searchRequest.source().query(QueryBuilders.matchAllQuery()).size(5); // One policy for each space
            SearchResponse response = this.client.search(searchRequest).actionGet();

            BulkRequest bulkUpdateRequest = new BulkRequest();

            for (SearchHit hit : response.getHits().getHits()) {
                Map<String, Object> source = hit.getSourceAsMap();

                Map<String, Object> space = (Map<String, Object>) source.get(SPACE);
                if (space != null) {
                    String spaceName = (String) space.get("name");
                    if (Space.DRAFT.equals(spaceName) || Space.TESTING.equals(spaceName)) {
                        log.info("Skipping hash calculation for policy [{}] because it is in space [{}]", hit.getId(), spaceName);
                        continue;
                    }
                }

                // 1. Policy Hash
                List<String> spaceHashes = new ArrayList<>();
                spaceHashes.add(this.getHash(source));

                Map<String, Object> document = (Map<String, Object>) source.get(DOCUMENT);
                if (document != null && document.containsKey(INTEGRATIONS)) {
                    List<String> integrationIds = (List<String>) document.get(INTEGRATIONS);

                    for (String integrationId : integrationIds) {
                        Map<String, Object> integrationSource = this.getDocumentSource(integrationIndex, integrationId);
                        if (integrationSource == null) {
                            continue;
                        }

                        // 2. Integration Hash
                        spaceHashes.add(this.getHash(integrationSource));

                        Map<String, Object> integration = (Map<String, Object>) integrationSource.get(DOCUMENT);
                        if (integration != null) {
                            // 3. Decoders Hash
                            this.addHashes(integration, DECODERS, decoderIndex, spaceHashes);

                            // 4. KVDBs Hash
                            this.addHashes(integration, KVDBS, kvdbIndex, spaceHashes);

                            // 5. Rules Hash
                            this.addHashes(integration, RULES, ruleIndex, spaceHashes);
                        }
                    }
                }

                // Calculate space Hash
                String spaceHash = this.hash(String.join("", spaceHashes));

                // Prepare Update
                Map<String, Object> updateMap = new HashMap<>();
                Map<String, Object> spaceMap = (Map<String, Object>) source.getOrDefault(SPACE, new HashMap<>());
                Map<String, Object> hashMap = (Map<String, Object>) spaceMap.getOrDefault("hash", new HashMap<>());

                hashMap.put("sha256", spaceHash);
                spaceMap.put("hash", hashMap);
                updateMap.put(SPACE, spaceMap);

                bulkUpdateRequest.add(new UpdateRequest(policyIndex, hit.getId())
                    .doc(updateMap, XContentType.JSON));
            }

            if (bulkUpdateRequest.numberOfActions() > 0) {
                this.client.bulk(bulkUpdateRequest).actionGet();
                log.info("Updated policy hashes for consumer [{}]", consumer);
            }

        } catch (Exception e) {
            log.error("Error calculating policy hashes: {}", e.getMessage(), e);
        }
    }

    /**
     * Add all the hashes of the same resource type in the given integration to the spaceHashes array.
     *
     * @param integration   integration to walk
     * @param resource      resource type (rule, decoder, kvdb)
     * @param resourceIndex resouce index
     * @param spaceHashes   space hashes array
     */
    private void addHashes(Map<String, Object> integration, String resource, String resourceIndex, List<String> spaceHashes) {
        if (integration.containsKey(resource)) {
            List<String> kvdbIds = (List<String>) integration.get(resource);
            for (String id : kvdbIds) {
                Map<String, Object> kvdbSource = this.getDocumentSource(resourceIndex, id);
                if (kvdbSource != null) {
                    spaceHashes.add(this.getHash(kvdbSource));
                }
            }
        }
    }

    /**
     * Helper to get document source by ID from an index.
     * Returns null if index or document does not exist.
     */
    private Map<String, Object> getDocumentSource(String index, String id) {
        try {
            GetResponse response = this.client.prepareGet(index, id).get();
            if (response.isExists()) {
                return response.getSourceAsMap();
            } else {
                log.info("Document [{}] not found in index [{}]", id, index);
            }
        } catch (Exception e) {
            log.info("Error retrieving document [{}] from index [{}]: {}", id, index, e.getMessage());
        }
        return null;
    }

    /**
     * Helper to extract sha256 hash from document source.
     */
    private String getHash(Map<String, Object> source) {
        if (source.containsKey("hash")) {
            Map<String, Object> hashObj = (Map<String, Object>) source.get("hash");
            return (String) hashObj.getOrDefault("sha256", "");
        }
        return "";
    }

    /**
     * Computes SHA-256 hash of a list of strings concatenated.
     */
    private String hash(String payload) {
        try {
            byte[] hash = MessageDigest
                .getInstance("SHA-256")
                .digest(payload.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            log.error("Error hashing content", e);
            return "";
        }
    }
}
