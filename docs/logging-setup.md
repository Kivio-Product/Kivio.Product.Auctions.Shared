# Sistema de Logging con Grafana Loki

## Descripción

Este sistema de logging implementa una solución completa de logging estructurado usando Grafana Loki, siguiendo los principios de Clean Architecture. Proporciona una interfaz simple y limpia para enviar logs a Grafana Cloud con fallback automático a consola.

## Características

- **Logging estructurado en JSON** con campos contextuales
- **Integración con Grafana Cloud Loki** con autenticación básica
- **Fallback automático a consola** si Loki no está disponible
- **Logging por capas** (Domain, Application, Infrastructure)
- **Configuración por variables de entorno**
- **Niveles de log configurables** (debug, info, warn, error)

## Configuración

### Variables de Entorno

```bash
# Configuración de Loki
LOKI_ENABLED=true
LOKI_URL=https://logs-prod-XXX.grafana.net/loki/api/v1/push
LOKI_USERNAME=tu_usuario
LOKI_PASSWORD=tu_password

# Configuración del servicio
SERVICE_NAME=kivio-auctions
ENVIRONMENT=production
LOG_LEVEL=info
```

### Ejemplo de Configuración .env

```env
LOKI_ENABLED=true
LOKI_URL=https://logs-prod-012345.grafana.net/loki/api/v1/push
LOKI_USERNAME=123456
LOKI_PASSWORD=glc_eyJrIjoiYWJjZGVmZ2hpai...
SERVICE_NAME=kivio-auctions-api
ENVIRONMENT=production
LOG_LEVEL=info
```

## Uso

### 1. Inicialización Básica

```go
import (
    infrastructureLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/logging"
)

// Obtener el repositorio de loggers (singleton)
loggerRepo := infrastructureLogging.GetLoggerRepository()
defer loggerRepo.Close()

// Obtener un logger básico
logger := loggerRepo.GetLogger()
```

### 2. Domain Event Logging

```go
import (
    "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/logging"
)

// Crear logger para eventos de dominio
eventLogger := logging.NewDomainEventLogger(loggerRepo.GetLogger())

// Registrar cambios de estado
eventLogger.LogRuleStateChange(ctx, "rule-123", "Created", "Active")
eventLogger.LogOfferStateChange(ctx, "offer-456", "Created", "Offered")
eventLogger.LogOrderCreated(ctx, "order-789", "customer-100", 299.99)
```

### 3. Service Level Logging

```go
import (
    applicationLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/application/logging"
)

// Crear logger para servicios de aplicación
serviceLogger := applicationLogging.NewServiceLogger(loggerRepo, "RuleService")

// Log de inicio de operación
serviceLogger.LogServiceStart(ctx, "CreateRule", map[string]interface{}{
    "user_id": "user-123",
    "rule_type": "auction",
})

// Log de finalización exitosa
serviceLogger.LogServiceEnd(ctx, "CreateRule", duration, map[string]interface{}{
    "rule_id": "rule-new-123",
})

// Log de error
serviceLogger.LogServiceError(ctx, "CreateRule", err, map[string]interface{}{
    "user_id": "user-123",
})
```

### 4. Infrastructure Logging

```go
import (
    infrastructureLogging "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/infrastructure/logging"
)

// Crear logger para infraestructura
infraLogger := infrastructureLogging.NewInfrastructureLogger(loggerRepo, "DynamoDBRepo")

// Log de operaciones de base de datos
infraLogger.LogDatabaseQuery(ctx, "Rules", "GetById", duration, true, map[string]interface{}{
    "rule_id": "rule-123",
})

// Log de operaciones S3
infraLogger.LogS3Operation(ctx, "PutObject", "bucket", "key", duration, true, fields)
```

### 5. Logging Directo

```go
logger := loggerRepo.GetLogger().WithService("MyService")

logger.Debug(ctx, "Debug message", map[string]interface{}{"key": "value"})
logger.Info(ctx, "Info message", map[string]interface{}{"user_id": "123"})
logger.Warn(ctx, "Warning message", map[string]interface{}{"threshold": 80})
logger.Error(ctx, "Error occurred", err, map[string]interface{}{"retry": 3})
```

## Niveles de Log

- **debug**: Información detallada para desarrollo
- **info**: Información general de operaciones
- **warn**: Advertencias que no impiden el funcionamiento
- **error**: Errores que requieren atención

## Campos Estándar en Logs

Todos los logs incluyen automáticamente:

```json
{
  "level": "info",
  "message": "Operation completed",
  "timestamp": "2025-01-15T10:30:00Z",
  "service": "RuleService",
  "context": {
    "user_id": "123",
    "operation": "CreateRule"
  },
  "error": "error message if present"
}
```

## Labels en Loki

Los logs se organizan en Loki con estos labels:

- `service`: Nombre del servicio
- `level`: Nivel del log
- `environment`: Entorno (development, staging, production)

## Fallback y Tolerancia a Fallos

- Si Loki no está configurado o falla, automáticamente usa logging a consola
- Los logs se envían de forma asíncrona para no bloquear la aplicación
- Timeout de 5 segundos para envío a Loki

## Consultas de Ejemplo en Grafana

```logql
# Todos los logs de un servicio
{service="RuleService"}

# Errores en los últimos 5 minutos
{level="error"} | json | __error__ = ""

# Logs de un usuario específico
{service="RuleService"} | json | context_user_id = "user-123"

# Operaciones de base de datos lentas
{event_type="database_operation"} | json | duration_ms > 1000
```

## Ejemplo Completo

Ver `logging_example.go` para un ejemplo completo de uso de todas las funcionalidades.

## Mejores Prácticas

1. **Usar logging estructurado**: Siempre incluir campos contextuales relevantes
2. **No loggear información sensible**: Evitar passwords, tokens, datos personales
3. **Usar el nivel apropiado**: Debug para desarrollo, Info para operaciones, Error para fallos
4. **Incluir contexto**: user_id, operation_id, correlation_id cuando sea posible
5. **Medir duración**: Para operaciones importantes, incluir tiempo de ejecución