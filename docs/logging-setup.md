# Grafana Loki Logging Setup

Este documento explica cómo configurar y usar el sistema de logging centralizado con Grafana Loki en el proyecto Kivio Auctions Shared.

## Configuración

### Variables de Entorno

Para configurar el sistema de logging, puedes usar las siguientes variables de entorno:

#### Configuración de Loki
```bash
LOKI_ENABLED=true                    # Habilitar/deshabilitar Loki (default: false)
LOKI_URL=http://localhost:3100       # URL del servidor Loki
LOKI_USERNAME=                       # Usuario para autenticación (opcional)
LOKI_PASSWORD=                       # Contraseña para autenticación (opcional)  
LOKI_TENANT_ID=                      # Tenant ID para multi-tenancy (opcional)
LOKI_TIMEOUT=30                      # Timeout en segundos (default: 30)
```

#### Configuración del Servicio
```bash
SERVICE_NAME=kivio-auctions-shared   # Nombre del servicio
ENVIRONMENT=development              # Entorno (development, staging, production)
SERVICE_VERSION=1.0.0               # Versión del servicio
```

#### Configuración de Console
```bash
CONSOLE_LOGGING_ENABLED=true        # Habilitar logging en consola (default: true)
CONSOLE_LOGGING_FORMAT=json         # Formato: json, text (default: json)
```

#### Configuración de Niveles de Log
```bash
LOG_LEVEL=info                       # Nivel por defecto: debug, info, warn, error
LOG_LEVEL_DOMAIN=info               # Nivel específico para domain layer
LOG_LEVEL_APPLICATION=info          # Nivel específico para application layer
LOG_LEVEL_INFRASTRUCTURE=info       # Nivel específico para infrastructure layer
```

## Uso Básico

### 1. Inicialización

```go
import (
    "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/logging"
)

// Inicializar el sistema de logging
initializer, err := logging.NewLoggingInitializer()
if err != nil {
    log.Fatal("Failed to initialize logging:", err)
}

loggerRepo, err := initializer.InitializeLogger()
if err != nil {
    log.Fatal("Failed to create logger repository:", err)
}
```

### 2. Uso en Domain Layer

```go
import (
    "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

// Logging de eventos de dominio
eventLogger := logging.NewDomainEventLogger(loggerRepo.GetLogger())

// Ejemplo: Log de cambio de estado de regla
eventLogger.LogRuleStateChange(ctx, ruleID, "Created", "Active")

// Ejemplo: Log de creación de oferta
eventLogger.LogOfferCreated(ctx, offerID, userID, 150.50)
```

### 3. Uso en Application Layer

```go
import (
    applicationLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/logging"
)

// Crear un service logger
serviceLogger := applicationLogging.NewServiceLogger(loggerRepo, "RuleService")

// Log inicio de operación
serviceLogger.LogServiceStart(ctx, "RuleService", "CreateRule", logging.Fields{
    "external_id": externalID,
    "item_id": itemID,
})

// Log operación exitosa
serviceLogger.LogServiceSuccess(ctx, "RuleService", "CreateRule", duration, logging.Fields{
    "rule_id": newRule.ID,
})

// Log error
serviceLogger.LogServiceError(ctx, "RuleService", "CreateRule", err, duration, logging.Fields{
    "external_id": externalID,
})
```

### 4. Uso en Infrastructure Layer

```go
import (
    infrastructureLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/logging"
)

// Crear un infrastructure logger
infraLogger := infrastructureLogging.NewInfrastructureLogger(loggerRepo, "DynamoDBRepository")

// Log operación de base de datos
infraLogger.LogDatabaseQuery(ctx, "Rules", "GetById", duration, true, logging.Fields{
    "rule_id": ruleID,
})

// Log llamada a API externa
infraLogger.LogExternalAPICall(ctx, "EcommerceAPI", "/api/items", "GET", 200, duration, logging.Fields{
    "item_id": itemID,
})
```

## Ejemplos Avanzados

### Logging con Context Fields

```go
// Crear logger con campos contextuales
logger := loggerRepo.GetLogger().
    WithUserID(userID).
    WithAuctionID(auctionID).
    WithFields(logging.Fields{
        "session_id": sessionID,
        "request_id": requestID,
    })

logger.Info(ctx, "User action performed", logging.Fields{
    "action": "place_bid",
    "amount": 100.00,
})
```

### HTTP Middleware con Logging

```go
import (
    "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/tools"
)

// Usar el middleware de logging actualizado
router.Use(tools.RequestLogger(loggerRepo))
```

### Búsqueda en Loki

#### Consultas LogQL básicas

```logql
# Todos los logs del servicio
{service="kivio-auctions-shared"}

# Logs de errores únicamente
{service="kivio-auctions-shared"} |= "ERROR"

# Logs de un usuario específico
{service="kivio-auctions-shared"} | json | user_id="12345"

# Logs de operaciones de base de datos
{service="kivio-auctions-shared"} | json | component="DynamoDBRepository"

# Logs con duración mayor a 1 segundo
{service="kivio-auctions-shared"} | json | duration_ms > 1000
```

#### Métricas y Alertas

```logql
# Tasa de errores por minuto
sum(rate({service="kivio-auctions-shared"} |= "ERROR" [1m]))

# Tiempo de respuesta promedio
avg_over_time({service="kivio-auctions-shared"} | json | unwrap duration_ms [5m])

# Conteo de eventos por usuario
sum by (user_id) (count_over_time({service="kivio-auctions-shared"} | json [1h]))
```

## Estructura de Logs

Los logs generados siguen esta estructura JSON:

```json
{
    "timestamp": "2025-09-15T10:30:00.000Z",
    "level": "info",
    "message": "Service operation completed successfully", 
    "service": "kivio-auctions-shared",
    "environment": "development",
    "layer": "application",
    "component": "RuleService",
    "operation": "CreateRule",
    "duration_ms": 150,
    "status": "success",
    "rule_id": "rule-123",
    "user_id": "user-456",
    "request_id": "req-789"
}
```

## Deployment con Docker

### docker-compose.yml para desarrollo local

```yaml
version: '3.8'

services:
  loki:
    image: grafana/loki:2.9.0
    ports:
      - "3100:3100"
    command: -config.file=/etc/loki/local-config.yaml
    
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-storage:/var/lib/grafana
      
volumes:
  grafana-storage:
```

## Troubleshooting

### Problemas Comunes

1. **Logs no aparecen en Loki**
   - Verificar que LOKI_ENABLED=true
   - Verificar la URL de Loki
   - Revisar la conectividad de red

2. **Performance Issues**
   - Ajustar el nivel de logging
   - Implementar sampling para logs de alto volumen
   - Usar async logging para operaciones críticas

3. **Memoria/Disk Usage**
   - Configurar retention policies en Loki
   - Implementar log rotation
   - Monitorear el tamaño de logs

### Debug Mode

Para habilitar debug logging:

```bash
LOG_LEVEL=debug
LOG_LEVEL_INFRASTRUCTURE=debug
```

Esto proporcionará información detallada sobre todas las operaciones del sistema.