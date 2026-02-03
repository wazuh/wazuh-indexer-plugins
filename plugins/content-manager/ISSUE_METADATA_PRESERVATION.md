# Issue: Metadata Preservation in PUT Operations for Decoders and KVDBs

## Problem Description

When performing a PUT operation on decoders and kvdbs, the entire document content is completely replaced. This behavior causes a critical issue where the `metadata.author.date` field (creation date) is lost if it's not included in the request payload.

## Current Behavior

1. **PUT `/decoders/{decoder_id}`**: The entire decoder document is replaced with the new payload
2. **PUT `/kvdbs/{kvdb_id}`**: The entire kvdb document is replaced with the new payload

During these operations:
- The `metadata.author.modified` timestamp is correctly updated to the current time
- However, the `metadata.author.date` (creation date) is **not preserved** from the existing document
- If the user's request doesn't include `metadata.author.date`, this field is lost
- The entire `metadata` object can be modified by the user, which should not be allowed

## Expected Behavior

1. **Metadata should be read-only**: The entire `metadata` object should not be modifiable by users through PUT operations
2. **Creation date preservation**: The `metadata.author.date` field should always be preserved from the original document and never overwritten
3. **Modified timestamp**: The `metadata.author.modified` field should be automatically updated by the system to the current timestamp
4. **Document replacement**: Only the non-metadata portions of the document should be replaceable by the user

## Affected Endpoints

- `PUT /_plugins/content-manager/decoders/{decoder_id}`
- `PUT /_plugins/content-manager/kvdbs/{kvdb_id}`

## Solution Requirements

1. Perform a GET operation on the index to retrieve the existing document by its ID
2. Extract and preserve the `metadata.author.date` field from the existing document
3. Merge the preserved `date` field with the new document payload
4. Update `metadata.author.modified` to the current timestamp
5. Ignore any `metadata` fields provided by the user in the PUT request payload
6. Apply the same logic to both decoders and kvdbs

**Note**: KVDBs will be handled in a separate development effort.

## Technical Details

### Current Implementation

In `RestPutDecoderAction.java`:
- Line 251: `decoderIndex.create(decoderId, this.buildDecoderPayload(resourceNode))` completely replaces the document
- Line 292-314: `updateTimestampMetadata()` only sets `modified` but doesn't preserve `date` from existing document

### Implementation Status

✅ **Decoders**: Implemented in `RestPutDecoderAction.java`
- Added `preserveMetadataAndUpdateTimestamp()` method that:
  - Retrieves the existing document from the index
  - Preserves the entire `metadata` object from the existing document
  - Updates only `metadata.author.modified` with the current timestamp
  - Ignores any metadata provided in the PUT request payload
  - Ensures `metadata.author.date` cannot be modified

⏳ **KVDBs**: Will be handled in a separate development effort
- `RestPutKvdbAction.java` remains as a stub for future implementation

