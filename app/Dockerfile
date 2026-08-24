# =============================================================================
# Dockerfile
#
# Construye la imagen de producción del servicio "api" (ver el servicio
# "api" en docker-compose.yml, que utiliza este Dockerfile con
# context: ./app). Genera una imagen mínima que contiene únicamente las
# dependencias de producción y el código fuente necesario para ejecutar
# la API Bank-Grade JWT, sin herramientas de desarrollo ni archivos
# innecesarios.
# =============================================================================

# Imagen base: Node.js 22 en su variante Alpine (liviana, menor
# superficie de ataque). Fija una versión mayor explícita (22) en lugar
# de "latest" para garantizar builds reproducibles.
FROM node:22-alpine

# Directorio de trabajo dentro del contenedor. Todas las instrucciones
# siguientes (COPY, RUN, CMD) se ejecutan relativas a esta ruta.
WORKDIR /app

# Fuerza el entorno de ejecución a "production". Afecta el
# comportamiento interno de dependencias como Express (por ejemplo,
# deshabilita mensajes de depuración) y complementa a NODE_ENV en
# env.js, aunque en runtime dicho valor normalmente se sobrescribe vía
# la variable de entorno inyectada por docker-compose.yml.
ENV NODE_ENV=production

# Copia únicamente los manifiestos de dependencias (package.json y
# package-lock.json) antes que el resto del código fuente. Esto
# aprovecha la cache de capas de Docker: mientras las dependencias no
# cambien, "npm ci" no se vuelve a ejecutar en builds posteriores,
# acelerando el proceso de build.
COPY package*.json ./

# Instala las dependencias exactas definidas en package-lock.json
# ("ci" en lugar de "install" garantiza una instalación reproducible),
# omitiendo las dependencias de desarrollo (--omit=dev) para mantener
# la imagen final lo más pequeña y libre de herramientas innecesarias.
RUN npm ci --omit=dev

# Copia el código fuente de la aplicación una vez instaladas las
# dependencias, aprovechando nuevamente la cache de capas: los cambios
# en el código no invalidan la capa de "npm ci" anterior.
COPY src ./src

# Cambia al usuario no privilegiado "node" (incluido por defecto en la
# imagen base), en lugar de ejecutar el proceso como root. Reduce el
# impacto de una eventual vulnerabilidad dentro del contenedor.
USER node

# Documenta el puerto en el que la aplicación escucha dentro del
# contenedor (ver src/app.js y PORT en env.js). Es informativo: no
# publica el puerto por sí mismo, eso lo define docker-compose.yml.
EXPOSE 3000

# Comando de arranque del contenedor: ejecuta directamente el punto de
# entrada de la aplicación (src/server.js) con Node.js, en lugar de
# depender de un gestor de procesos como npm, evitando una capa
# intermedia de proceso innecesaria.
CMD ["node", "src/server.js"]