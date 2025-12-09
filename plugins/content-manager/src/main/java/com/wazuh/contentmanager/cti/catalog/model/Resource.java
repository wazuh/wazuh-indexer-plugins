package com.wazuh.contentmanager.cti.catalog.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Base model representing a generic catalog resource within the CTI context.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Resource {
    private static final Logger log = LogManager.getLogger(Resource.class);
    private static final Gson gson = new Gson();

    // JSON Key Constants
    private static final String JSON_DOCUMENT_KEY = "document";
    private static final String JSON_METADATA_KEY = "metadata";
    private static final String JSON_CUSTOM_FIELDS_KEY = "custom_fields";
    private static final String JSON_DATASET_KEY = "dataset";
    private static final String JSON_RELATED_KEY = "related";
    private static final String JSON_SIGMA_ID_KEY = "sigma_id";

    @JsonProperty("document")
    private Map<String, Object> document;

    @JsonProperty("hash")
    private Map<String, String> hash;

    @JsonProperty("space")
    private Map<String, String> space;

    /**
     * Default constructor.
     */
    public Resource() {
    }

    /**
     * Factory method to create a {@link Resource} instance from a raw Gson {@link JsonObject}.
     *
     * @param payload The raw JSON object containing the resource data.
     * @return A fully populated {@link Resource} instance.
     */
    public static Resource fromPayload(JsonObject payload) {
        Resource resource = new Resource();
        populateResource(resource, payload);
        return resource;
    }

    /**
     * Populates the common fields of a Resource instance.
     *
     * @param resource The resource instance to populate.
     * @param payload  The source JSON payload.
     */
    protected static void populateResource(Resource resource, JsonObject payload) {
        // 1. Process Document
        if (payload.has(JSON_DOCUMENT_KEY) && payload.get(JSON_DOCUMENT_KEY).isJsonObject()) {
            JsonObject rawDoc = payload.getAsJsonObject(JSON_DOCUMENT_KEY).deepCopy();
            preprocessDocument(rawDoc);

            resource.setDocument(gson.fromJson(rawDoc, Map.class));

            // 2. Calculate Hash
            String hashStr = calculateSha256(rawDoc);
            if (hashStr != null) {
                Map<String, String> hashMap = new HashMap<>();
                hashMap.put("sha256", hashStr);
                resource.setHash(hashMap);
            }
        }

        // 3. Set Space
        // TODO: Change To the real logic once CTI is ready
        Map<String, String> spaceMap = new HashMap<>();
        String spaceName = Space.FREE.toString().toLowerCase(Locale.ROOT);
        spaceMap.put("name", spaceName);
        resource.setSpace(spaceMap);
    }

    /**
     * Sanitizes the document by removing internal or unnecessary fields.
     *
     * @param document The JSON object representing the document content.
     */
    protected static void preprocessDocument(JsonObject document) {
        if (document.has(JSON_METADATA_KEY) && document.get(JSON_METADATA_KEY).isJsonObject()) {
            JsonObject metadata = document.getAsJsonObject(JSON_METADATA_KEY);
            if (metadata.has(JSON_CUSTOM_FIELDS_KEY)) {
                metadata.remove(JSON_CUSTOM_FIELDS_KEY);
            }
            if (metadata.has(JSON_DATASET_KEY)) {
                metadata.remove(JSON_DATASET_KEY);
            }
        }

        if (document.has(JSON_RELATED_KEY)) {
            JsonElement relatedElement = document.get(JSON_RELATED_KEY);
            if (relatedElement.isJsonObject()) {
                sanitizeRelatedObject(relatedElement.getAsJsonObject());
            } else if (relatedElement.isJsonArray()) {
                JsonArray relatedArray = relatedElement.getAsJsonArray();
                for (JsonElement element : relatedArray) {
                    if (element.isJsonObject()) sanitizeRelatedObject(element.getAsJsonObject());
                }
            }
        }
    }

    /**
     * Helper method to sanitize a single "related" object.
     *
     * @param relatedObj The JSON object inside the "related" field.
     */
    private static void sanitizeRelatedObject(JsonObject relatedObj) {
        if (relatedObj.has(JSON_SIGMA_ID_KEY)) {
            relatedObj.add("id", relatedObj.get(JSON_SIGMA_ID_KEY));
            relatedObj.remove(JSON_SIGMA_ID_KEY);
        }
    }

    /**
     * Calculates the SHA-256 checksum of a JSON Object.
     *
     * @param json The JSON object to hash.
     * @return The Hexadecimal string representation of the SHA-256 hash, or {@code null} if calculation fails.
     */
    protected static String calculateSha256(JsonObject json) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(json.toString().getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder(2 * encodedhash.length);
            for (byte b : encodedhash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            log.error("Failed to calculate SHA-256 hash", e);
            return null;
        }
    }

    /**
     * Gets the document content.
     *
     * @return A Map representing the document.
     */
    public Map<String, Object> getDocument() {
        return document;
    }

    /**
     * Sets the document content.
     *
     * @param document A Map representing the document.
     */
    public void setDocument(Map<String, Object> document) {
        this.document = document;
    }

    /**
     * Gets the hash map containing checksums.
     *
     * @return A Map containing hash algorithms and values.
     */
    public Map<String, String> getHash() {
        return hash;
    }

    /**
     * Sets the hash map.
     *
     * @param hash A Map containing hash algorithms and values.
     */
    public void setHash(Map<String, String> hash) {
        this.hash = hash;
    }

    /**
     * Gets the space definition.
     *
     * @return A Map containing space details.
     */
    public Map<String, String> getSpace() {
        return space;
    }

    /**
     * Sets the space definition.
     *
     * @param space A Map containing space details.
     */
    public void setSpace(Map<String, String> space) {
        this.space = space;
    }

    @Override
    public String toString() {
        return "Resource{" +
            "document=" + document +
            ", hash=" + hash +
            ", space=" + space +
            '}';
    }
}
