import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { KeycloakAuthService } from '../keycloak-auth.service';

export interface KeycloakAuthOptions {
    roles?: string[];
    clientRoles?: Record<string, string[]>;
    requireAllRoles?: boolean;
    optional?: boolean; // Si es true, permite acceso sin token
}

export const KEYCLOAK_AUTH_KEY = 'keycloak_auth';

export const KeycloakAuth = (options: KeycloakAuthOptions = {}) => {
    return (target: any, propertyKey: string, descriptor: PropertyDescriptor) => {
        Reflect.defineMetadata(KEYCLOAK_AUTH_KEY, options, descriptor.value);
        return descriptor;
    };
};

@Injectable()
export class KeycloakAuthGuard implements CanActivate {
    constructor(
        private reflector: Reflector,
        private keycloakService: KeycloakAuthService,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const options = this.reflector.getAllAndOverride<KeycloakAuthOptions>(KEYCLOAK_AUTH_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        // Extraer el token del header Authorization
        const authHeader = request.headers.authorization;

        // Si es opcional y no hay token, permitir acceso
        if (options?.optional && (!authHeader || !authHeader.startsWith('Bearer '))) {
            return true;
        }

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new UnauthorizedException('Token de autorización requerido');
        }

        const token = authHeader.substring(7);

        // Validar el token
        const validationResult = await this.keycloakService.validateToken(token);
        if (!validationResult.valid) {
            throw new UnauthorizedException(validationResult.error || 'Token inválido');
        }

        // Agregar el usuario decodificado a la request
        request.user = validationResult.decoded;

        // Si no hay opciones de roles, solo validar que el token sea válido
        if (!options || (!options.roles && !options.clientRoles)) {
            return true;
        }

        // Verificar roles del realm
        if (options.roles && options.roles.length > 0) {
            const userRoles = validationResult.decoded?.realm_access?.roles || [];
            const hasRealmRole = options.requireAllRoles
                ? options.roles.every((role) => userRoles.includes(role))
                : options.roles.some((role) => userRoles.includes(role));

            if (!hasRealmRole) {
                throw new UnauthorizedException('Roles insuficientes');
            }
        }

        // Verificar roles de cliente
        if (options.clientRoles) {
            const userClientRoles = validationResult.decoded?.resource_access || {};

            for (const [clientId, requiredRoles] of Object.entries(options.clientRoles)) {
                const userRoles = userClientRoles[clientId]?.roles || [];
                const hasClientRole = options.requireAllRoles
                    ? requiredRoles.every((role) => userRoles.includes(role))
                    : requiredRoles.some((role) => userRoles.includes(role));

                if (!hasClientRole) {
                    throw new UnauthorizedException(`Roles insuficientes para el cliente ${clientId}`);
                }
            }
        }

        return true;
    }
}
