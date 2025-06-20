import { Module } from '@nestjs/common';
import { KeycloakAuthModule } from '../src';

// Configuración para validación de tokens (frontend controla login)
const keycloakConfig = {
  serverUrl: 'http://localhost:8080',
  realm: 'my-realm',
  clientId: 'my-client',
  clientSecret: 'my-client-secret', // Necesario para refresh y logout
  verifyTokenAudience: true,
  verifyTokenIssuer: true,
  tokenExpirationTolerance: 30, // segundos
};

@Module({
  imports: [
    KeycloakAuthModule.forRoot({
      config: keycloakConfig,
    }),
  ],
})
export class AppModule {}

// Ejemplo de uso en Next.js frontend
export const nextjsExample = `
// En tu aplicación Next.js, el flujo sería así:

// 1. Instalar keycloak-js
// npm install keycloak-js

// 2. Configurar Keycloak en el frontend
import Keycloak from 'keycloak-js';

const keycloak = new Keycloak({
  url: 'http://localhost:8080',
  realm: 'my-realm',
  clientId: 'my-client'
});

// 3. Inicializar y hacer login
await keycloak.init({
  onLoad: 'login-required'
});

// 4. Obtener el token
const token = keycloak.token;

// 5. Enviar requests al backend con el token
const response = await fetch('/api/auth/protected', {
  headers: {
    'Authorization': \`Bearer \${token}\`
  }
});

// 6. Para validar el token en el backend
const validateResponse = await fetch('/api/auth/validate', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ token })
});

// 7. Para renovar el token
const refreshResponse = await fetch('/api/auth/refresh', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ refreshToken: keycloak.refreshToken })
});

// 8. Para logout
const logoutResponse = await fetch('/api/auth/logout', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ refreshToken: keycloak.refreshToken })
});
`;

// Ejemplo de controlador personalizado
export class CustomControllerExample {
  constructor(private keycloakService: any) {}

  // Endpoint que solo valida el token
  async validateTokenFromFrontend(token: string) {
    return await this.keycloakService.validateToken(token);
  }

  // Endpoint que obtiene información del usuario
  async getUserFromToken(token: string) {
    return await this.keycloakService.getUserInfo(token);
  }
} 