# Keycloak Auth Library

Librería para validación de tokens Keycloak en NestJS cuando el frontend controla la autenticación.

## Características

- 🎫 Validación de tokens JWT desde frontend
- 🔄 Renovación de tokens
- 👤 Obtención de información de usuario
- 🛡️ Guards de autorización con roles
- 🏷️ Decoradores para obtener usuario actual
- 🔧 Configuración flexible
- 🌐 Optimizada para frontend (Next.js, React, etc.)

## Instalación

```bash
npm install @monderks/nestjs-keycloak-auth
```

## Configuración

### Configuración Básica

```typescript
import { Module } from '@nestjs/common';
import { KeycloakAuthModule } from '@monderks/nestjs-keycloak-auth';

@Module({
  imports: [
    KeycloakAuthModule.forRoot({
      config: {
        serverUrl: 'http://localhost:8080',
        realm: 'my-realm',
        clientId: 'my-client',
        clientSecret: 'my-client-secret', // Necesario para refresh y logout
        verifyTokenAudience: true,
        verifyTokenIssuer: true,
        tokenExpirationTolerance: 30, // segundos
      },
    }),
  ],
})
export class AppModule {}
```

### Configuración Asíncrona

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { KeycloakAuthModule } from '@monderks/nestjs-keycloak-auth';

@Module({
  imports: [
    ConfigModule.forRoot(),
    KeycloakAuthModule.forRootAsync({
      useFactory: (configService: ConfigService) => ({
        serverUrl: configService.get('KEYCLOAK_SERVER_URL'),
        realm: configService.get('KEYCLOAK_REALM'),
        clientId: configService.get('KEYCLOAK_CLIENT_ID'),
        clientSecret: configService.get('KEYCLOAK_CLIENT_SECRET'),
        verifyTokenAudience: true,
        verifyTokenIssuer: true,
      }),
      inject: [ConfigService],
    }),
  ],
})
export class AppModule {}
```

## ¿Cómo usar la librería?

Esta librería **no expone controladores**. Solo provee servicios, guards y decoradores para que tú crees tus propios endpoints y lógica de negocio.

### Ejemplo de uso en tu propio controlador

```typescript
import { Controller, Get, Post, Body, UseGuards } from '@nestjs/common';
import { KeycloakAuthService, KeycloakAuthGuard, KeycloakAuth, CurrentUser } from '@monderks/nestjs-keycloak-auth';
import { DecodedToken } from '@monderks/nestjs-keycloak-auth';

@Controller('api/auth')
export class AuthController {
  constructor(private keycloakService: KeycloakAuthService) {}

  @Post('validate')
  async validateToken(@Body() body: { token: string }) {
    return await this.keycloakService.validateToken(body.token);
  }

  @Get('protected')
  @UseGuards(KeycloakAuthGuard)
  @KeycloakAuth()
  getProtectedData(@CurrentUser() user: DecodedToken) {
    return {
      message: 'Datos protegidos',
      user,
    };
  }
}
```

## Flujo de Autenticación

### 1. Frontend (Next.js/React) - Login

```typescript
// Instalar keycloak-js
// npm install keycloak-js

import Keycloak from 'keycloak-js';

// Configurar Keycloak
const keycloak = new Keycloak({
  url: 'http://localhost:8080',
  realm: 'my-realm',
  clientId: 'my-client'
});

// Inicializar y hacer login
await keycloak.init({
  onLoad: 'login-required'
});

// Obtener el token
const token = keycloak.token;
```

### 2. Frontend - Enviar Requests al Backend

```typescript
// Endpoint protegido
const response = await fetch('/api/auth/protected', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});

// Validar token
const validateResponse = await fetch('/api/auth/validate', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ token })
});

// Renovar token
const refreshResponse = await fetch('/api/auth/refresh', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ refreshToken: keycloak.refreshToken })
});

// Logout
const logoutResponse = await fetch('/api/auth/logout', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ refreshToken: keycloak.refreshToken })
});
```

## Endpoints recomendados (tú los creas)

- POST `/api/auth/validate` → Valida un token
- POST `/api/auth/user-info` → Obtiene info del usuario
- POST `/api/auth/refresh` → Renueva el token
- POST `/api/auth/logout` → Logout
- GET `/api/auth/protected` → Endpoint protegido
- GET `/api/auth/admin` → Endpoint con roles
- GET `/api/auth/public` → Endpoint público

## API Reference

### KeycloakAuthService

#### Métodos de Validación
- `validateToken(token: string): Promise<TokenValidationResult>`
- `getUserInfo(accessToken: string): Promise<DecodedToken>`
- `refreshToken(refreshToken: string): Promise<RefreshTokenResult>`
- `logout(refreshToken: string): Promise<boolean>`
- `hasRole(userId: string, roleName: string, clientId?: string): Promise<boolean>`

### Decoradores

- `@CurrentUser()` - Obtiene el usuario autenticado de la request
- `@CurrentUser('sub')` - Obtiene una propiedad específica del usuario

### Guards

- `@KeycloakAuth()` - Protege rutas con validación de tokens
- `@KeycloakAuth({ roles: ['admin'] })` - Requiere roles específicos
- `@KeycloakAuth({ clientRoles: { 'client-id': ['role'] } })` - Requiere roles de cliente
- `@KeycloakAuth({ optional: true })` - Permite acceso sin token

## Variables de Entorno

```env
KEYCLOAK_SERVER_URL=http://localhost:8080
KEYCLOAK_REALM=my-realm
KEYCLOAK_CLIENT_ID=my-client
KEYCLOAK_CLIENT_SECRET=my-client-secret
```

## Configuración Avanzada

### Opciones de Configuración Completas

```typescript
const keycloakConfig = {
  serverUrl: 'http://localhost:8080',
  realm: 'my-realm',
  clientId: 'my-client',
  clientSecret: 'my-client-secret',
  
  // Clave pública del realm (opcional, se obtiene automáticamente)
  publicKey: '-----BEGIN PUBLIC KEY-----...',
  
  // Opciones de validación
  verifyTokenAudience: true,
  verifyTokenIssuer: true,
  tokenExpirationTolerance: 30, // segundos
};
```

## Ejemplos de Uso

### Middleware Personalizado

```typescript
@Injectable()
export class KeycloakMiddleware implements NestMiddleware {
  constructor(private keycloakService: KeycloakAuthService) {}

  async use(req: Request, res: Response, next: Function) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (token) {
      const validation = await this.keycloakService.validateToken(token);
      if (validation.valid) {
        req.user = validation.decoded;
      }
    }
    
    next();
  }
}
```

### Hook de React para Next.js

```typescript
// hooks/useKeycloak.ts
import { useState, useEffect } from 'react';
import Keycloak from 'keycloak-js';

export const useKeycloak = () => {
  const [keycloak, setKeycloak] = useState<Keycloak | null>(null);
  const [authenticated, setAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const kc = new Keycloak({
      url: process.env.NEXT_PUBLIC_KEYCLOAK_URL,
      realm: process.env.NEXT_PUBLIC_KEYCLOAK_REALM,
      clientId: process.env.NEXT_PUBLIC_KEYCLOAK_CLIENT_ID,
    });

    kc.init({
      onLoad: 'check-sso',
      silentCheckSsoRedirectUri: window.location.origin + '/silent-check-sso.html',
    }).then((auth) => {
      setKeycloak(kc);
      setAuthenticated(auth);
      setLoading(false);
    });
  }, []);

  return { keycloak, authenticated, loading };
};
```

## Contribuir

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para detalles.
