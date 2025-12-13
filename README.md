# Lodgic Auth

Servicio de autenticación para generar y verificar hashes de contraseñas usando bcrypt.

## Características

- Endpoint de salud (`/health`)
- Generación de hashes bcrypt (`/hash`)
- Verificación de contraseñas (`/verify`)
- Autenticación mediante API key
- Dockerizado y listo para producción

## Configuración

### Variables de entorno

- `PORT`: Puerto del servidor (default: 3000)
- `LODGIC_AUTH_API_KEY`: API key para autenticación
- `BCRYPT_ROUNDS`: Número de rondas de bcrypt (default: 10)

## Instalación

```bash
npm install
```

## Uso

### Desarrollo local

```bash
npm start
```

### Docker

```bash
docker build -t lodgic-auth .
docker run -p 3000:3000 -e LODGIC_AUTH_API_KEY=tu_api_key lodgic-auth
```

## API Endpoints

### Health Check
```
GET /health
```

### Hash Password
```
POST /hash
Headers: x-lodgic-key: <API_KEY>
Body: { "password": "tu_contraseña" }
```

### Verify Password
```
POST /verify
Headers: x-lodgic-key: <API_KEY>
Body: { "password": "tu_contraseña", "hash": "hash_a_verificar" }
```

## Licencia

MIT
