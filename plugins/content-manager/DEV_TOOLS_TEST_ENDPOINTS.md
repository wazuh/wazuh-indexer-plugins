# Endpoints para probar en Dev Tools de Wazuh

## 0. POST - Crear una Integration en Draft Space

Si no tienes ninguna integración en draft space, puedes crear una directamente en el índice `.cti-integrations`:

```json
PUT .cti-integrations/_doc/i_<genera-un-uuid-aqui>
{
  "document": {
    "id": "<mismo-uuid-sin-prefijo-i_>",
    "title": "Test Integration",
    "description": "Integración de prueba para testing",
    "category": "security",
    "enabled": true,
    "author": "Wazuh",
    "date": "2026-01-01T00:00:00.000Z",
    "rules": [],
    "decoders": []
  },
  "hash": {
    "sha256": "placeholder_hash_will_be_calculated_automatically"
  },
  "space": {
    "name": "draft"
  }
}
```

**Ejemplo completo con UUID:**
```json
PUT .cti-integrations/_doc/i_550e8400-e29b-41d4-a716-446655440000
{
  "document": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "title": "Test Integration",
    "description": "Integración de prueba para testing",
    "category": "security",
    "enabled": true,
    "author": "Wazuh",
    "date": "2026-01-01T00:00:00.000Z",
    "rules": [],
    "decoders": []
  },
  "hash": {
    "sha256": "placeholder"
  },
  "space": {
    "name": "draft"
  }
}
```

**Nota:** El hash `sha256` puede ser un placeholder, pero idealmente debería calcularse del contenido del `document`. Para pruebas, puedes usar cualquier string.

**Después de crear la integración, verifica que se creó correctamente:**
```json
GET .cti-integrations/_doc/i_550e8400-e29b-41d4-a716-446655440000
```

**O busca todas las integraciones en draft:**
```json
GET .cti-integrations/_search
{
  "query": {
    "term": {
      "space.name": "draft"
    }
  }
}
```

---

## 0.1. GET - Obtener Integration IDs en Draft Space

Para obtener un `integration_id` válido que esté en el espacio "draft", usa esta consulta:

```json
GET .cti-integrations/_search
{
  "query": {
    "term": {
      "space.name": "draft"
    }
  },
  "size": 10,
  "_source": ["document.id", "document.title"]
}
```

**Obtener solo el primer ID disponible (más rápido):**
```json
GET .cti-integrations/_search
{
  "query": {
    "term": {
      "space.name": "draft"
    }
  },
  "size": 1,
  "_source": ["document.id", "document.title"]
}
```

**Obtener solo los IDs (sin el documento completo):**
```json
GET .cti-integrations/_search
{
  "query": {
    "term": {
      "space.name": "draft"
    }
  },
  "size": 10,
  "_source": ["document.id"]
}
```

**Ejemplo de respuesta:**
```json
{
  "hits": {
    "hits": [
      {
        "_id": "i_12345678-1234-1234-1234-123456789abc",
        "_source": {
          "document": {
            "id": "12345678-1234-1234-1234-123456789abc",
            "title": "Nombre de la Integración"
          }
        }
      }
    ]
  }
}
```

**Nota:** Usa el valor de `document.id` como `integration_id` en tus peticiones POST (por ejemplo, en `POST /_plugins/_content_manager/decoders` o `POST /_plugins/_content_manager/rules`).

---

## 1. POST - Crear un Decoder

```json
POST /_plugins/_content_manager/decoders
Content-Type: application/json

{
  "type": "decoder",
  "integration": "i_test-integration-uuid",
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

**Nota:** Necesitarás un `integration_id` válido que esté en el espacio "draft". 
- Si no tienes ninguna, crea una usando la sección **0. POST - Crear una Integration en Draft Space**
- Si ya tienes integraciones, consulta la sección **0.1. GET - Obtener Integration IDs en Draft Space** para obtener un ID existente

---

## 2. GET - Obtener el Decoder (búsqueda directa en el índice)

Después de crear el decoder, obtén su ID de la respuesta. Luego busca el documento en el índice:

```json
GET .cti-decoders/_doc/d_<decoder-id>
```

**Ejemplo:**
```json
GET .cti-decoders/_doc/d_82e215c4-988a-4f64-8d15-b98b2fc03a4f
```

**O busca todos los decoders:**
```json
GET .cti-decoders/_search
{
  "query": {
    "match_all": {}
  }
}
```

**O busca por nombre:**
```json
GET .cti-decoders/_search
{
  "query": {
    "term": {
      "document.name": "decoder/test-decoder/0"
    }
  }
}
```

---

## 3. PUT - Actualizar el Decoder (VALIDAR PRESERVACIÓN DE METADATA)

**IMPORTANTE:** Este es el endpoint clave para validar que solo el `metadata.author.date` se preserve.

```json
PUT /_plugins/_content_manager/decoders/d_<decoder-id>
Content-Type: application/json

{
  "type": "decoder",
  "resource": {
    "name": "decoder/test-decoder/0",
    "enabled": true,
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

**Nota:** 
- El `metadata.author.date` NO debe estar en el request
- El sistema debe preservar SOLO el `date` original del documento existente
- Los demás campos de metadata (`title`, `description`, `author.name`) SÍ se pueden actualizar si vienen en el request
- El campo `metadata.author.modified` se actualiza automáticamente con la fecha actual

---

## 4. GET - Verificar que el metadata se preservó correctamente

Después del PUT, vuelve a obtener el decoder para verificar:

```json
GET .cti-decoders/_doc/d_<decoder-id>
```

**Validaciones esperadas:**
1. ✅ `document.metadata.author.date` debe ser la fecha original (no debe cambiar) - **SOLO ESTE CAMPO SE PRESERVA**
2. ✅ `document.metadata.author.modified` debe ser una fecha más reciente (actualizada automáticamente)
3. ✅ `document.metadata.title` y `document.metadata.description` deben tener los valores nuevos del PUT (se actualizan)
4. ✅ `document.metadata.author.name` debe tener el valor nuevo del PUT (se actualiza)

---

## Ejemplo completo paso a paso

### Paso 1: Crear decoder
```json
POST /_plugins/_content_manager/decoders
{
  "type": "decoder",
  "integration": "i_tu-integration-id-aqui",
  "resource": {
    "name": "decoder/metadata-test/0",
    "enabled": true,
    "metadata": {
      "title": "Metadata Test Decoder",
      "description": "Test para validar preservación",
      "author": {
        "name": "Wazuh"
      }
    },
    "decoder": "<decoder><prematch>test</prematch></decoder>"
  }
}
```

**Respuesta esperada:**
```json
{
  "message": "Decoder created successfully with ID: d_xxxx-xxxx-xxxx",
  "status": 201
}
```

### Paso 2: Obtener el decoder creado
```json
GET .cti-decoders/_search
{
  "query": {
    "term": {
      "document.name": "decoder/metadata-test/0"
    }
  }
}
```

**Anota el `_id` del resultado** (ejemplo: `d_82e215c4-988a-4f64-8d15-b98b2fc03a4f`)

**Anota también el `document.metadata.author.date`** del resultado (ejemplo: `2026-02-02T18:30:00.000Z`)

### Paso 3: Actualizar el decoder (SIN incluir `date` en metadata, pero SÍ incluir otros campos)
```json
PUT /_plugins/_content_manager/decoders/d_82e215c4-988a-4f64-8d15-b98b2fc03a4f
{
  "type": "decoder",
  "resource": {
    "name": "decoder/metadata-test/0",
    "enabled": false,
    "metadata": {
      "title": "Metadata Test Decoder UPDATED",
      "description": "Descripción completamente nueva",
      "author": {
        "name": "Usuario de Prueba"
      }
    },
    "decoder": "<decoder><prematch>updated test</prematch></decoder>"
  }
}
```

**Importante:** 
- NO incluyas `metadata.author.date` en el request (se preserva automáticamente)
- SÍ puedes incluir `metadata.title`, `metadata.description`, `metadata.author.name` (se actualizarán)

### Paso 4: Verificar preservación
```json
GET .cti-decoders/_doc/d_82e215c4-988a-4f64-8d15-b98b2fc03a4f
```

**Resultado esperado:**
```json
{
  "_index": ".cti-decoders",
  "_id": "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f",
  "_source": {
    "document": {
      "name": "decoder/metadata-test/0",
      "enabled": false,
      "metadata": {
        "title": "Metadata Test Decoder UPDATED",  // ✅ Actualizado
        "description": "Descripción completamente nueva",  // ✅ Actualizado
        "author": {
          "name": "Usuario de Prueba",  // ✅ Actualizado
          "date": "2026-02-02T18:30:00.000Z",  // ✅ PRESERVADO (mismo que antes)
          "modified": "2026-02-02T18:35:00.000Z"  // ✅ ACTUALIZADO (nueva fecha)
        }
      },
      "decoder": "<decoder><prematch>updated test</prematch></decoder>"  // ✅ Actualizado
    }
  }
}
```

---

## Checklist de validación

- [ ] El decoder se crea correctamente con POST
- [ ] El decoder se puede obtener con GET
- [ ] Al hacer PUT, el `metadata.author.date` se preserva (no cambia) - **SOLO ESTE CAMPO SE PRESERVA**
- [ ] Al hacer PUT, el `metadata.author.modified` se actualiza automáticamente
- [ ] Al hacer PUT, otros campos de metadata (`title`, `description`, `author.name`) se actualizan correctamente si vienen en el request
- [ ] El resto del documento (`name`, `enabled`, `decoder`) se actualiza correctamente

---

## Notas importantes

1. **El `integration_id` es requerido para crear decoders.** Si no tienes uno, necesitarás crear una integración primero.

2. **El formato del ID:** Los decoders en el índice tienen el prefijo `d_` (ejemplo: `d_82e215c4-988a-4f64-8d15-b98b2fc03a4f`)

3. **El endpoint PUT preserva SOLO el `metadata.author.date`** - todos los demás campos de metadata (`title`, `description`, `author.name`) se pueden actualizar si vienen en el request. El campo `metadata.author.modified` se actualiza automáticamente.

4. **Para obtener el ID del decoder después de crearlo**, puedes:
   - Usar la respuesta del POST (si incluye el ID)
   - Buscar en el índice `.cti-decoders` por el nombre del decoder
   - Buscar en la integración asociada (campo `document.decoders`)

---

# Endpoints para probar KVDBs

## 1. POST - Crear un KVDB

```json
POST /_plugins/_content_manager/kvdbs
Content-Type: application/json

{
  "type": "kvdb",
  "integration": "i_test-integration-uuid",
  "resource": {
    "name": "kvdb/test-kvdb/0",
    "enabled": true,
    "space": {
      "name": "draft"
    },
    "metadata": {
      "title": "Test KVDB",
      "description": "KVDB de prueba para validar preservación de metadata",
      "author": {
        "name": "Wazuh"
      }
    }
  }
}
```

**Nota:** Necesitarás un `integration_id` válido que esté en el espacio "draft". 
- Si no tienes ninguna, crea una usando la sección **0. POST - Crear una Integration en Draft Space**
- Si ya tienes integraciones, consulta la sección **0.1. GET - Obtener Integration IDs en Draft Space** para obtener un ID existente

---

## 2. GET - Obtener el KVDB (búsqueda directa en el índice)

Después de crear el KVDB, obtén su ID de la respuesta. Luego busca el documento en el índice:

```json
GET .cti-kvdbs/_doc/d_<kvdb-id>
```

**Ejemplo:**
```json
GET .cti-kvdbs/_doc/d_82e215c4-988a-4f64-8d15-b98b2fc03a4f
```

**O busca todos los KVDBs:**
```json
GET .cti-kvdbs/_search
{
  "query": {
    "match_all": {}
  }
}
```

**O busca por nombre:**
```json
GET .cti-kvdbs/_search
{
  "query": {
    "term": {
      "document.name": "kvdb/test-kvdb/0"
    }
  }
}
```

---

## 3. PUT - Actualizar el KVDB (VALIDAR PRESERVACIÓN DE METADATA)

**IMPORTANTE:** Este es el endpoint clave para validar que solo el `metadata.author.date` se preserve.

```json
PUT /_plugins/_content_manager/kvdbs/d_<kvdb-id>
Content-Type: application/json

{
  "type": "kvdb",
  "integration": "i_test-integration-uuid",
  "resource": {
    "name": "kvdb/test-kvdb/0",
    "enabled": true,
    "space": {
      "name": "draft"
    },
    "metadata": {
      "title": "Test KVDB UPDATED",
      "description": "Descripción actualizada - el date NO debe cambiar",
      "author": {
        "name": "Usuario Actualizado"
      }
    }
  }
}
```

**Nota:** 
- El `metadata.author.date` NO debe estar en el request
- El sistema debe preservar SOLO el `date` original del documento existente
- Los demás campos de metadata (`title`, `description`, `author.name`) SÍ se pueden actualizar si vienen en el request
- El campo `metadata.author.modified` se actualiza automáticamente con la fecha actual
- El `integration` debe ser el mismo que se usó al crear el KVDB

---

## 4. GET - Verificar que el metadata se preservó correctamente

Después del PUT, vuelve a obtener el KVDB para verificar:

```json
GET .cti-kvdbs/_doc/d_<kvdb-id>
```

**Validaciones esperadas:**
1. ✅ `document.metadata.author.date` debe ser la fecha original (no debe cambiar) - **SOLO ESTE CAMPO SE PRESERVA**
2. ✅ `document.metadata.author.modified` debe ser una fecha más reciente (actualizada automáticamente)
3. ✅ `document.metadata.title` y `document.metadata.description` deben tener los valores nuevos del PUT (se actualizan)
4. ✅ `document.metadata.author.name` debe tener el valor nuevo del PUT (se actualiza)

---

## Ejemplo completo paso a paso para KVDBs

### Paso 1: Crear KVDB
```json
POST /_plugins/_content_manager/kvdbs
{
  "type": "kvdb",
  "integration": "i_tu-integration-id-aqui",
  "resource": {
    "name": "kvdb/metadata-test/0",
    "enabled": true,
    "space": {
      "name": "draft"
    },
    "metadata": {
      "title": "Metadata Test KVDB",
      "description": "Test para validar preservación",
      "author": {
        "name": "Wazuh"
      }
    }
  }
}
```

**Respuesta esperada:**
```json
{
  "message": "KVDB created successfully with ID: d_xxxx-xxxx-xxxx",
  "status": 202
}
```

### Paso 2: Obtener el KVDB creado
```json
GET .cti-kvdbs/_search
{
  "query": {
    "term": {
      "document.name": "kvdb/metadata-test/0"
    }
  }
}
```

**Anota el `_id` del resultado** (ejemplo: `d_82e215c4-988a-4f64-8d15-b98b2fc03a4f`)

**Anota también el `document.metadata.author.date`** del resultado (ejemplo: `2026-02-02T18:30:00.000Z`)

### Paso 3: Actualizar el KVDB (SIN incluir `date` en metadata, pero SÍ incluir otros campos)
```json
PUT /_plugins/_content_manager/kvdbs/d_82e215c4-988a-4f64-8d15-b98b2fc03a4f
{
  "type": "kvdb",
  "integration": "i_tu-integration-id-aqui",
  "resource": {
    "name": "kvdb/metadata-test/0",
    "enabled": false,
    "space": {
      "name": "draft"
    },
    "metadata": {
      "title": "Metadata Test KVDB UPDATED",
      "description": "Descripción completamente nueva",
      "author": {
        "name": "Usuario de Prueba"
      }
    }
  }
}
```

**Importante:** 
- NO incluyas `metadata.author.date` en el request (se preserva automáticamente)
- SÍ puedes incluir `metadata.title`, `metadata.description`, `metadata.author.name` (se actualizarán)
- Debes incluir el mismo `integration` que usaste al crear el KVDB

### Paso 4: Verificar preservación
```json
GET .cti-kvdbs/_doc/d_82e215c4-988a-4f64-8d15-b98b2fc03a4f
```

**Resultado esperado:**
```json
{
  "_index": ".cti-kvdbs",
  "_id": "d_82e215c4-988a-4f64-8d15-b98b2fc03a4f",
  "_source": {
    "document": {
      "name": "kvdb/metadata-test/0",
      "enabled": false,
      "metadata": {
        "title": "Metadata Test KVDB UPDATED",  // ✅ Actualizado
        "description": "Descripción completamente nueva",  // ✅ Actualizado
        "author": {
          "name": "Usuario de Prueba",  // ✅ Actualizado
          "date": "2026-02-02T18:30:00.000Z",  // ✅ PRESERVADO (mismo que antes)
          "modified": "2026-02-02T18:35:00.000Z"  // ✅ ACTUALIZADO (nueva fecha)
        }
      }
    }
  }
}
```

---

## Checklist de validación para KVDBs

- [ ] El KVDB se crea correctamente con POST
- [ ] El KVDB se puede obtener con GET
- [ ] Al hacer PUT, el `metadata.author.date` se preserva (no cambia) - **SOLO ESTE CAMPO SE PRESERVA**
- [ ] Al hacer PUT, el `metadata.author.modified` se actualiza automáticamente
- [ ] Al hacer PUT, otros campos de metadata (`title`, `description`, `author.name`) se actualizan correctamente si vienen en el request
- [ ] El resto del documento (`name`, `enabled`, `space`) se actualiza correctamente

---

## Notas importantes para KVDBs

1. **El `integration_id` es requerido para crear y actualizar KVDBs.** Si no tienes uno, necesitarás crear una integración primero.

2. **El formato del ID:** Los KVDBs en el índice tienen el prefijo `d_` (ejemplo: `d_82e215c4-988a-4f64-8d15-b98b2fc03a4f`)

3. **El endpoint PUT preserva SOLO el `metadata.author.date`** - todos los demás campos de metadata (`title`, `description`, `author.name`) se pueden actualizar si vienen en el request. El campo `metadata.author.modified` se actualiza automáticamente.

4. **Para obtener el ID del KVDB después de crearlo**, puedes:
   - Usar la respuesta del POST (si incluye el ID)
   - Buscar en el índice `.cti-kvdbs` por el nombre del KVDB
   - Buscar en la integración asociada (campo `document.kvdbs`)

5. **Los KVDBs solo pueden actualizarse en el espacio "draft"** - si intentas actualizar un KVDB que no está en draft, recibirás un error.

