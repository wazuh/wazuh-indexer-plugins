### Description

Implement metadata preservation in PUT operations for **Decoders**. This fix ensures that the `metadata.author.date` field (creation date) is preserved from the existing document when updating a decoder, preventing data loss during update operations.

**Key Changes:**
- The `metadata.author.date` field is now automatically preserved from the existing document and cannot be modified through PUT operations
- Other metadata fields (`title`, `description`, `author.name`) can be updated if provided in the request
- The `metadata.author.modified` timestamp is automatically updated to the current time on every PUT operation
- If no metadata is provided in the request, all existing metadata is preserved (including the `date` field)

### Evidence

<details><summary>Screenshots</summary>
<p>

<!-- Add screenshots here showing:
1. Before: PUT operation losing the date field
2. After: PUT operation preserving the date field
3. Test results showing the preservation works correctly
-->

</p>
</details>

### Issues Resolved
Resolves: https://github.com/wazuh/wazuh-indexer-plugins/issues/766

## Manual Testing

The following curl commands can be executed from **Wazuh Dashboard Dev Tools** to test the decoder PUT endpoint:

### 1. Create a Decoder (if needed)

```json
POST /_plugins/_content_manager/decoders
{
  "type": "decoder",
  "integration": "i_<your-integration-id>",
  "resource": {
    "name": "decoder/test-decoder/0",
    "enabled": true,
    "metadata": {
      "title": "Test Decoder",
      "description": "Decoder de prueba para validar preservación de metadata",
      "author": {
        "name": "Wazuh"
      }
    },
    "decoder": "<decoder>\n  <prematch>test pattern</prematch>\n</decoder>"
  }
}
```

**Note:** Save the decoder ID from the response (e.g., `d_7406ae53-3037-47e5-9f0b-21a6043478b2`)

### 2. Get the Decoder to Verify Initial State

```json
GET .cti-decoders/_doc/d_<decoder-id>
```

**Note:** Save the `document.metadata.author.date` value from the response (e.g., `2026-02-02T19:02:39.333929991Z`)

### 3. Update the Decoder (Test Metadata Preservation)

```json
PUT /_plugins/_content_manager/decoders/d_<decoder-id>
{
  "type": "decoder",
  "resource": {
    "name": "decoder/test-decoder/0",
    "enabled": false,
    "metadata": {
      "title": "Test Decoder UPDATED",
      "description": "Descripción actualizada - el date NO debe cambiar",
      "author": {
        "name": "Usuario Actualizado"
      }
    },
    "decoder": "<decoder>\n  <prematch>updated pattern</prematch>\n</decoder>"
  }
}
```

**Expected Behavior:**
- ✅ `metadata.author.date` should remain the same as the original value
- ✅ `metadata.title` should be updated to "Test Decoder UPDATED"
- ✅ `metadata.description` should be updated to "Descripción actualizada - el date NO debe cambiar"
- ✅ `metadata.author.name` should be updated to "Usuario Actualizado"
- ✅ `metadata.author.modified` should be updated to the current timestamp

### 4. Verify the Update

```json
GET .cti-decoders/_doc/d_<decoder-id>
```

**Validation Checklist:**
- [ ] `document.metadata.author.date` matches the original value (preserved)
- [ ] `document.metadata.author.modified` is a newer timestamp than the original
- [ ] `document.metadata.title` has the updated value
- [ ] `document.metadata.description` has the updated value
- [ ] `document.metadata.author.name` has the updated value
- [ ] `document.enabled` is updated to `false`
- [ ] `document.decoder` has the updated pattern

### 5. Test Update Without Metadata (Preserve All Existing Metadata)

```json
PUT /_plugins/_content_manager/decoders/d_<decoder-id>
{
  "type": "decoder",
  "resource": {
    "name": "decoder/test-decoder/0",
    "enabled": true
  }
}
```

**Expected Behavior:**
- ✅ All existing metadata (including `date`) should be preserved
- ✅ Only `metadata.author.modified` should be updated to current timestamp
- ✅ `document.enabled` should be updated to `true`

