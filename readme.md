# BANK-GRADE JWT

## JWT + Redis Session + Refresh Token Rotation

Arquitectura de autenticación y control de sesiones inspirada en patrones utilizados en sistemas financieros y aplicaciones de alta criticidad.

---

## Tabla de contenidos

1. [Propósito](#1-propósito)
2. [Bank-Grade Mindset](#2-bank-grade-mindset)
3. [Arquitectura](#3-arquitectura)
4. [¿Por qué no solamente JWT?](#4-por-qué-no-solamente-jwt)
5. [JWT + Redis Session](#5-jwt--redis-session)
6. [¿Qué almacenamos en Redis?](#6-qué-almacenamos-en-redis)
7. [Estructura del proyecto](#7-estructura-del-proyecto)
8. [Responsabilidad de cada componente](#8-responsabilidad-de-cada-componente)
9. [Flujo de login](#9-flujo-de-login)
10. [Access Token](#10-access-token)
11. [Refresh Token](#11-refresh-token)
12. [¿Cuándo se utiliza el Refresh Token?](#12-cuándo-se-utiliza-el-refresh-token)
13. [Refresh Token Rotation](#13-refresh-token-rotation)
14. [Reuse Detection](#14-reuse-detection)
15. [Condición de carrera](#15-condición-de-carrera)
16. [Redis + Lua](#16-redis--lua)
17. [¿Por qué usamos hash del Refresh Token?](#17-por-qué-usamos-hash-del-refresh-token)
18. [Flujo completo](#18-flujo-completo)
19. [Endpoints](#19-endpoints)
20. [Logout](#20-logout)
21. [Docker](#21-docker)
22. [Redis](#22-redis)
23. [Ver sesiones activas](#23-ver-sesiones-activas)
24. [Eliminar una sesión específica](#24-eliminar-una-sesión-específica)
25. [Revocar una sesión sin eliminarla](#25-revocar-una-sesión-sin-eliminarla)
26. [Eliminar todas las sesiones](#26-eliminar-todas-las-sesiones)
27. [Ver información de Redis](#27-ver-información-de-redis)
28. [Variables de entorno](#28-variables-de-entorno)
29. [.env.example](#29-envexample)
30. [Seguridad de secretos](#30-seguridad-de-secretos)
31. [Contexto bancario](#31-contexto-bancario)
32. [Ejemplo de escenario bancario](#32-ejemplo-de-escenario-bancario)
33. [¿Por qué esto es útil en sistemas bancarios?](#33-por-qué-esto-es-útil-en-sistemas-bancarios)
34. [JWT + Redis](#34-jwt--redis)
35. [¿Es realmente una arquitectura "bank-grade"?](#35-es-realmente-una-arquitectura-bank-grade)
36. [Ventajas de esta arquitectura](#36-ventajas-de-esta-arquitectura)
37. [Trade-off](#37-trade-off)
38. [El concepto principal](#38-el-concepto-principal)
39. [Flujo final](#39-flujo-final)
40. [Objetivo final del entrenamiento](#40-objetivo-final-del-entrenamiento)

---

## 1. Propósito

El objetivo de este proyecto es demostrar que una arquitectura de autenticación no debería depender únicamente de verificar la firma de un JWT.

Una implementación básica podría funcionar así:

```text
Cliente
   |
   | Login
   v
API
   |
   | JWT
   v
Cliente
   |
   | Authorization: Bearer JWT
   v
API
   |
   | Verificar firma
   v
Acceso permitido
```

El problema aparece cuando el JWT sigue siendo criptográficamente válido pero la sesión del usuario ya no debería estar activa.

Por ejemplo:

- El usuario cerró sesión.
- El token fue robado.
- El dispositivo fue comprometido.
- El usuario inició sesión desde otro dispositivo.
- La sesión fue revocada por seguridad.
- Se detectó reutilización de un Refresh Token.
- El sistema necesita invalidar una sesión inmediatamente.

Un JWT firmado correctamente no puede resolver por sí solo todos estos escenarios.

Por esta razón agregamos una capa de control de sesiones utilizando Redis.

## 2. Bank-Grade Mindset

Un sistema básico pregunta:

> ¿El JWT es válido?

Una arquitectura orientada a sistemas críticos pregunta además:

> ¿Esta sesión debería seguir siendo válida?

El objetivo de este laboratorio es demostrar esa diferencia.

## 3. Arquitectura

La arquitectura implementada utiliza:

```text
                  CLIENT
             Web / Mobile App
                     |
                     v
                  NGINX
              Reverse Proxy
                     |
                     v
              Node.js / Express
                     |
             +-------+-------+
             |               |
             v               v
          JWT Auth        Redis
             |               |
             v               v
        Authorization      Session
                            Control
```

Los componentes principales son:

- Node.js
- Express
- JSON Web Tokens (JWT)
- Redis
- ioredis
- Nginx
- Docker
- Docker Compose

No se utiliza una base de datos.

Los usuarios utilizados para el laboratorio están definidos mediante variables de entorno.

## 4. ¿Por qué no solamente JWT?

JWT tiene una característica muy importante: una vez emitido, el servidor puede validar su firma sin tener que consultar una sesión almacenada en una base de datos.

Esto resulta muy útil para arquitecturas distribuidas.

Sin embargo, tiene una consecuencia:

```text
JWT válido
    |
    v
Hasta que expire
```

Si un JWT tiene una duración de 15 minutos y fue robado:

```text
Token comprometido
       |
       v
JWT válido
       |
       v
El servidor podría aceptarlo
       |
       v
Hasta que expire
```

Esto genera un problema:

> ¿Cómo invalidamos inmediatamente un token que todavía es criptográficamente válido?

Aquí aparece Redis.

## 5. JWT + Redis Session

En esta arquitectura el JWT sigue siendo importante.

El JWT contiene información como:

```json
{
    "sub": "user-001",
    "sid": "session-id",
    "role": "customer",
    "jti": "token-id",
    "iss": "bank-grade-api",
    "aud": "bank-grade-client",
    "iat": 1787602511,
    "exp": 1787603411
}
```

Pero ahora tenemos una segunda capa:

```text
JWT
 |
 | firma válida
 v
Middleware
 |
 | sid
 v
Redis
 |
 | sesión activa
 v
Acceso permitido
```

Por lo tanto:

```text
JWT válido + Sesión válida = Acceso permitido
```

La firma del JWT demuestra que el token fue emitido por nuestro sistema y no fue alterado.

Redis permite controlar si la sesión asociada todavía debe considerarse válida.

## 6. ¿Qué almacenamos en Redis?

Para cada sesión tenemos una estructura similar a:

```text
session:{sessionId}
```

Ejemplo:

```text
session:995455d8-986e-4137-8b8b-72afa77e1e94
```

La sesión contiene información como:

- userId
- username
- role
- jti
- refreshTokenId
- refreshTokenHash
- status
- createdAt

Ejemplo conceptual:

```text
session:995455d8-986e-4137-8b8b-72afa77e1e94

userId              = user-001
username            = demo@bank.local
role                = customer
jti                 = 82fda408-...
refreshTokenId      = 5b8c...
refreshTokenHash    = ...
status              = active
createdAt           = 2026-08-24T...
```

## 7. Estructura del proyecto

```text
bank-grade-jwt/
│
├── docker-compose.yml
├── Dockerfile
├── package.json
├── package-lock.json
├── .env
├── .env.example
├── .gitignore
├── README.md
│
├── nginx/
│   └── nginx.conf
│
└── src/
    │
    ├── app.js
    ├── server.js
    │
    ├── config/
    │   └── env.js
    │
    ├── controllers/
    │   └── auth.controller.js
    │
    ├── middleware/
    │   └── auth.middleware.js
    │
    ├── routes/
    │   ├── auth.routes.js
    │   └── protected.routes.js
    │
    ├── services/
    │   ├── auth.service.js
    │   └── session.service.js
    │
    └── utils/
        └── token.utils.js
```

## 8. Responsabilidad de cada componente

### config/env.js

Centraliza y valida las variables de entorno.

Ejemplo:

- `JWT_SECRET`
- `JWT_ACCESS_EXPIRES_IN`
- `REDIS_HOST`
- `REDIS_PORT`
- `APP_USER_ID`
- `APP_USERNAME`
- `APP_PASSWORD`

La aplicación falla rápidamente si una variable requerida no está configurada.

Esto evita arrancar la aplicación en un estado inconsistente.

### services/auth.service.js

Contiene la lógica principal de autenticación.

Responsabilidades:

- Login.
- Generación de Access Token.
- Generación de Refresh Token.
- Refresh Token Rotation.
- Generación de nuevos jti.
- Validación de sesiones.

### services/session.service.js

Es la capa encargada de interactuar con Redis.

Responsabilidades:

- Crear sesiones.
- Consultar sesiones.
- Rotar Refresh Tokens.
- Revocar sesiones.
- Eliminar sesiones.
- Ejecutar operaciones atómicas mediante Lua Script.

### middleware/auth.middleware.js

Protege endpoints.

Conceptualmente realiza:

```text
Authorization Header
        |
        v
Extraer JWT
        |
        v
Verificar firma
        |
        v
Verificar issuer
        |
        v
Verificar audience
        |
        v
Verificar expiración
        |
        v
Consultar sesión
        |
        v
Validar status
        |
        v
Permitir / Denegar
```

### routes/auth.routes.js

Define endpoints relacionados con autenticación.

Actualmente:

- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`

### routes/protected.routes.js

Contiene endpoints que requieren autenticación.

Ejemplo:

- `GET /api/protected`

## 9. Flujo de login

El usuario realiza:

```text
POST /api/auth/login
```

con:

```json
{
    "username": "demo@dmb.local",
    "password": "Demo123!"
}
```

La API genera:

- Access Token
- Refresh Token
- Session

El Access Token tiene una duración corta. Ejemplo: 15 minutos.

El Refresh Token tiene una duración mayor. Ejemplo: 30 días.

## 10. Access Token

El Access Token se utiliza para acceder a APIs protegidas.

Ejemplo:

```text
GET /api/protected
Authorization: Bearer ACCESS_TOKEN
```

El Access Token:

- Es de corta duración.
- Se utiliza para acceder a recursos.
- Contiene claims.
- Está firmado.
- No debe utilizarse como mecanismo permanente de sesión.

## 11. Refresh Token

El Refresh Token no se utiliza para consumir APIs protegidas.

Su función es obtener un nuevo Access Token.

Se utiliza:

```text
POST /api/auth/refresh
```

Ejemplo:

```json
{
    "refreshToken": "REFRESH_TOKEN"
}
```

La respuesta contiene:

```json
{
    "accessToken": "NEW_ACCESS_TOKEN",
    "refreshToken": "NEW_REFRESH_TOKEN",
    "tokenType": "Bearer",
    "expiresIn": "15m"
}
```

## 12. ¿Cuándo se utiliza el Refresh Token?

El cliente utiliza el Refresh Token cuando el Access Token está próximo a expirar o ya expiró.

Flujo:

```text
Login
  |
  +---- Access Token
  |
  +---- Refresh Token
           |
           v
      Access Token expira
           |
           v
      POST /refresh
           |
           v
    Nuevo Access Token
           |
           v
    Continúa la sesión
```

El usuario no necesita introducir nuevamente usuario y contraseña.

## 13. Refresh Token Rotation

Cada vez que se utiliza un Refresh Token correctamente, se genera otro.

Ejemplo:

```text
Refresh Token A
       |
       | /refresh
       v
Refresh Token B
```

El Refresh Token A deja de ser válido.

Posteriormente:

```text
Refresh Token B
       |
       | /refresh
       v
Refresh Token C
```

Y así sucesivamente.

La idea es que un Refresh Token tenga un uso limitado:

```text
A -> B -> C -> D -> E
```

No:

```text
A -> B
A -> B
A -> B
A -> B
```

## 14. Reuse Detection

Uno de los mecanismos más importantes de esta arquitectura es la detección de reutilización.

Supongamos que el Refresh Token A se utiliza correctamente:

```text
A -> B
```

El token A ya no debería volver a utilizarse.

Si posteriormente alguien intenta utilizar A, el sistema interpreta que puede existir un compromiso del token.

Entonces:

```text
Refresh Token A
       |
       v
Ya fue utilizado
       |
       v
REUSE DETECTED
       |
       v
Revocar sesión
```

La sesión completa pasa a:

```text
status = revoked
```

Esto es mucho más fuerte que simplemente rechazar el token.

## 15. Condición de carrera

La rotación de Refresh Tokens tiene un problema importante:

> ¿Qué ocurre si dos solicitudes utilizan simultáneamente el mismo Refresh Token?

Por ejemplo:

```text
Request A ----+
              |
              v
        Refresh Token A
              ^
              |
Request B ----+
```

Si hacemos:

```text
GET refresh token
        |
        v
validar
        |
        v
actualizar
```

como operaciones independientes, podemos tener una condición de carrera.

Ambas solicitudes podrían considerar válido el mismo Refresh Token.

## 16. Redis + Lua

Para resolver este problema utilizamos un Lua Script ejecutado directamente dentro de Redis.

La operación realiza:

1. Obtener sesión.
2. Verificar status.
3. Obtener hash del Refresh Token.
4. Comparar hash.
5. Actualizar Refresh Token.
6. Actualizar Refresh Token ID.
7. Actualizar JTI.

Todo como una única operación atómica.

Conceptualmente:

```text
Request A
    |
    v
+---------------------------+
| Redis Lua Script          |
|                           |
| validate                  |
| compare                   |
| rotate                    |
| update                    |
+---------------------------+
    |
    v
SUCCESS
```

Mientras otra solicitud simultánea encontrará que el Refresh Token ya cambió.

## 17. ¿Por qué usamos hash del Refresh Token?

No almacenamos el Refresh Token directamente en Redis.

No queremos:

```text
refreshToken = secreto-real
```

En su lugar almacenamos:

```text
refreshTokenHash = SHA256(refreshToken)
```

Cuando el cliente envía el Refresh Token:

```text
Refresh Token
      |
      v
SHA-256
      |
      v
Hash recibido
      |
      v
Comparar con Redis
```

Esto reduce el impacto si alguien obtiene acceso al contenido de Redis.

## 18. Flujo completo

```text
                         CLIENT
                    Web / Mobile App
                           |
                           | LOGIN
                           v
                     NGINX / API
                           |
                           v
                   Authentication
                           |
               +-----------+-----------+
               |                       |
               v                       v
        Access Token             Refresh Token
          15 minutos                30 días
               |                       |
               v                       v
        Protected API              Redis Session
               |                       |
               +-----------+-----------+
                           |
                           v
                    Session Control
                           |
                    +------+------+
                    |             |
                    v             v
                 active        revoked
                    |
                    v
                  ACCESS
```

## 19. Endpoints

### Login

```text
POST /api/auth/login
```

Ejemplo:

```bash
curl --request POST \
  --url http://localhost:8080/api/auth/login \
  --header 'Content-Type: application/json' \
  --data '{
    "username": "demo@dmb.local",
    "password": "Demo123!"
  }'
```

### Protected API

```text
GET /api/protected
```

Ejemplo:

```bash
curl --request GET \
  --url http://localhost:8080/api/protected \
  --header "Authorization: Bearer TU_ACCESS_TOKEN"
```

### Refresh

```text
POST /api/auth/refresh
```

Ejemplo:

```bash
curl --request POST \
  --url http://localhost:8080/api/auth/refresh \
  --header 'Content-Type: application/json' \
  --data '{
    "refreshToken": "TU_REFRESH_TOKEN"
  }'
```

## 20. Logout

El Logout invalida la sesión almacenada en Redis.

Conceptualmente:

```text
Cliente
   |
   | Logout
   v
API
   |
   v
Redis
   |
   v
Session revoked/deleted
```

El comportamiento exacto depende de la implementación del endpoint de logout.

## 21. Docker

Construir y levantar los servicios:

```bash
docker compose up -d --build
```

Ver contenedores:

```bash
docker compose ps
```

Ver logs:

```bash
docker compose logs -f
```

Ver logs de la API:

```bash
docker compose logs -f api
```

Ver logs de Nginx:

```bash
docker compose logs -f nginx
```

Detener los servicios:

```bash
docker compose down
```

Detener y eliminar volúmenes:

```bash
docker compose down -v
```

## 22. Redis

Entrar al contenedor de Redis:

```bash
docker exec -it bank-grade-redis redis-cli
```

## 23. Ver sesiones activas

Dentro de Redis:

```text
KEYS session:*
```

Ejemplo:

```text
1) "session:995455d8-986e-4137-8b8b-72afa77e1e94"
```

Consultar una sesión:

```text
HGETALL session:995455d8-986e-4137-8b8b-72afa77e1e94
```

Consultar únicamente el estado:

```text
HGET session:995455d8-986e-4137-8b8b-72afa77e1e94 status
```

Consultar el TTL:

```text
TTL session:995455d8-986e-4137-8b8b-72afa77e1e94
```

## 24. Eliminar una sesión específica

Desde Redis:

```text
DEL session:995455d8-986e-4137-8b8b-72afa77e1e94
```

Esto elimina la sesión.

## 25. Revocar una sesión sin eliminarla

También podemos modificar su estado:

```text
HSET session:995455d8-986e-4137-8b8b-72afa77e1e94 status revoked
```

Ahora:

```text
HGET session:995455d8-986e-4137-8b8b-72afa77e1e94 status
```

debería devolver:

```text
revoked
```

Esto permite demostrar una característica importante: el JWT puede seguir siendo criptográficamente válido, pero la sesión ya no está autorizada.

## 26. Eliminar todas las sesiones

Para el laboratorio se puede utilizar:

```text
KEYS session:*
```

y posteriormente eliminar las claves.

También puede utilizarse:

```text
FLUSHDB
```

**Importante:** `FLUSHDB` elimina todas las claves de la base de datos Redis seleccionada.

Este comando solo debe utilizarse en este laboratorio.

Nunca debe ejecutarse indiscriminadamente sobre un Redis productivo o compartido.

## 27. Ver información de Redis

Desde Redis:

```text
INFO
```

Ver memoria:

```text
INFO memory
```

Ver clientes:

```text
INFO clients
```

Ver estadísticas:

```text
INFO stats
```

## 28. Variables de entorno

La aplicación utiliza variables de entorno para evitar colocar configuración directamente dentro del código.

## 29. .env.example

El repositorio debe contener un archivo `.env.example`.

Este archivo sirve como plantilla para nuestras variables de entorno.

Ejemplo:

```env
NODE_ENV=development
PORT=3000

JWT_SECRET=change-this-secret
JWT_ACCESS_EXPIRES_IN=15m

REDIS_HOST=redis
REDIS_PORT=6379

APP_USER_ID=user-001
APP_USERNAME=demo@bank.local
APP_PASSWORD=change-this-password
APP_USER_ROLE=customer
```

El archivo `.env` real no debería ser incluido en Git.

Debe agregarse al `.gitignore`:

```text
.env
node_modules/
```

## 30. Seguridad de secretos

En este laboratorio utilizamos `.env` para simplificar el entrenamiento.

En producción no debería considerarse suficiente.

Los secretos deberían administrarse mediante mecanismos como:

- Secret Managers.
- Docker Secrets.
- Kubernetes Secrets.
- AWS Secrets Manager.
- Azure Key Vault.
- Google Secret Manager.
- HashiCorp Vault.

El objetivo del laboratorio es entender el concepto, no implementar una plataforma completa de gestión de secretos.

## 31. Contexto en servicios críticos

Un ejemplo son las aplicaciones bancarias que suelen tener múltiples canales de acceso:

```text
              BANCO
                |
       +--------+--------+
       |                 |
       v                 v
     WEB              MOBILE
       |                 |
       +--------+--------+
                |
                v
             APIs
                |
                v
        Authentication
                |
                v
        Session Control
```

Un mismo usuario puede tener:

- Sesión web.
- Sesión en aplicación móvil.
- Sesión en otro dispositivo.
- Sesiones concurrentes.
- Sesiones que deben ser revocadas.

Por eso el concepto de sesión puede ser mucho más importante que simplemente tener un JWT.

## 32. Ejemplo de escenario bancario

Imaginemos:

```text
Usuario
   |
   v
Aplicación móvil
   |
   v
Login
   |
   +---- Access Token
   |
   +---- Refresh Token
```

El usuario continúa utilizando la aplicación.

Después:

```text
Refresh Token
       |
       v
Access Token renovado
       |
       v
Nueva sesión/token
```

Si el sistema detecta una situación sospechosa:

```text
Dispositivo comprometido
       |
       v
Sesión identificada
       |
       v
Redis
       |
       v
status = revoked
```

A partir de ese momento la sesión deja de considerarse válida.

## 33. ¿Por qué esto es útil en sistemas críticos?

Porque una arquitectura de autenticación puede necesitar controlar:

- Sesiones activas.
- Dispositivos.
- Tokens.
- Renovaciones.
- Revocaciones.
- Reutilización de Refresh Tokens.
- Sesiones comprometidas.
- Accesos sospechosos.
- Cierre de sesión.
- Expiración.
- Políticas de seguridad.

El objetivo no es que Redis "reemplace" a JWT.

La idea es combinar las fortalezas de ambos.

## 34. JWT + Redis

JWT aporta:

- Firma
- Integridad
- Claims
- Expiración
- Issuer
- Audience
- Identidad

Redis aporta:

- Estado de sesión
- Revocación
- Control en tiempo real
- Rotación
- Invalidación
- Reuse Detection
- TTL
- Estado distribuido

Combinados:

```text
                JWT
                 +
               Redis
                 |
                 v
       Authentication + Session Control
```

## 35. ¿Es realmente esta arquitectura "bank-grade"?

El nombre BANK-GRADE JWT es utilizado como concepto didáctico.

Este laboratorio demuestra patrones de seguridad utilizados en sistemas de alta criticidad, pero una plataforma real requiere muchos controles adicionales.

Por ejemplo:

- MFA.
- Device Fingerprinting.
- Risk-Based Authentication.
- Rate Limiting.
- Fraud Detection.
- WAF.
- API Gateway.
- HSM.
- Gestión avanzada de secretos.
- Auditoría.
- SIEM.
- Monitoring.
- Distributed Tracing.
- Protección contra bots.
- Detección de anomalías.
- Políticas de Zero Trust.
- Gestión de dispositivos.
- Controles de cumplimiento.
- Cifrado.
- Alta disponibilidad.
- Disaster Recovery.

Por lo tanto, este proyecto es un laboratorio basado en patrones de seguridad, no una implementación completa de autenticación de tipo Bank-Grade.

## 36. Ventajas de esta arquitectura

**Mayor control**

El servidor mantiene información sobre la sesión.

**Revocación**

Una sesión puede invalidarse antes de que expire el JWT.

**Refresh Token Rotation**

Cada Refresh Token puede utilizarse una sola vez.

**Reuse Detection**

Permite detectar intentos de reutilización de tokens.

**Atomicidad**

Redis Lua permite ejecutar la rotación como una operación atómica.

**Expiración**

Redis TTL permite que las sesiones desaparezcan automáticamente.

**Escalabilidad**

Redis puede actuar como una capa compartida de sesiones entre múltiples instancias de la API.

Ejemplo:

```text
                  Load Balancer
                       |
          +------------+------------+
          |            |            |
          v            v            v
       API #1        API #2       API #3
          |            |            |
          +------------+------------+
                       |
                       v
                     Redis
                       |
                       v
               Session Control
```

Esto permite que cualquier instancia pueda consultar la misma sesión.

## 37. Trade-off

Esta arquitectura también introduce complejidad.

Ya no tenemos:

```text
JWT
  |
  v
Validar firma
```

Tenemos:

```text
JWT
 |
 v
Validar firma
 |
 v
Consultar Redis
 |
 v
Validar sesión
```

Esto significa:

- Dependencia adicional.
- Latencia adicional.
- Redis debe estar disponible.
- Se requiere administrar sesiones.
- Se requiere manejar expiración.
- Se debe diseñar correctamente la revocación.

Por eso no todos los sistemas necesitan esta arquitectura.

La decisión depende del nivel de seguridad y control requerido.

## 38. El concepto principal

Una autenticación robusta no debe limitarse a:

> ¿El token es válido?

Debe considerar:

- ¿El token es válido?
- ¿La sesión sigue activa?
- ¿El token no fue reutilizado?
- ¿La sesión no fue revocada?
- ¿La operación está autorizada?

Ese es el concepto principal de este laboratorio.

## 39. Flujo final

```text
                     LOGIN
                       |
                       v
              Validate credentials
                       |
                       v
                 Create Session
                       |
             +---------+---------+
             |                   |
             v                   v
       Access Token        Refresh Token
          15 min              30 days
             |                   |
             v                   v
       Protected API         Redis Session
             |                   |
             +---------+---------+
                       |
                       v
                  Access granted
                       |
                       v
                 Token expires
                       |
                       v
                    /refresh
                       |
                       v
              Atomic Rotation
                       |
              +--------+--------+
              |                 |
              v                 v
          Successful         Reuse
              |                 |
              v                 v
       New credentials    Revoke session
              |                 |
              v                 v
          Continue          Access denied
```

## 40. Objetivo final

El objetivo no es aprender simplemente a llamar `jwt.sign(...)`.

El objetivo es comprender que la seguridad de una API es un diseño completo.

Debemos pensar en:

```text
Identidad
   |
Autenticación
   |
Tokens
   |
Sesiones
   |
Autorización
   |
Revocación
   |
Rotación
   |
Detección
   |
Auditoría
```

Un JWT puede demostrar que un token fue firmado correctamente.

Una arquitectura de sesiones permite además responder:

> ¿Esta sesión todavía debería existir?

Ese es el cambio de mentalidad que busca demostrar este laboratorio.

---

### Bank-Grade Mindset

Los sistemas seguros no solo preguntan:

> "¿Este token es válido?"

También preguntan:

> "¿Esta sesión debería seguir siendo válida?"
