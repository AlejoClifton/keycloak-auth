// Módulo principal
export { KeycloakAuthModule } from '@/keycloak-auth.module';

// Servicio principal
export { KeycloakAuthService } from '@/keycloak-auth.service';

// Guard de autenticación
export { KeycloakAuthGuard, KeycloakAuth } from '@/guards/keycloak-auth.guard';

// Decorador para obtener usuario actual
export { CurrentUser } from '@/decorators/current-user.decorator';

// Interfaces y tipos
export * from '@/interfaces/keycloak-config.interface'; 