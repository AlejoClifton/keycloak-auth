import { Injectable, Inject, Logger } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import * as jwt from 'jsonwebtoken';
import { importJWK, jwtVerify, JWK } from 'jose';
import {
    KeycloakConfig,
    DecodedToken,
    TokenValidationResult,
    RefreshTokenResult,
} from './interfaces/keycloak-config.interface';

@Injectable()
export class KeycloakAuthService {
    private readonly logger = new Logger(KeycloakAuthService.name);
    private readonly httpClient: AxiosInstance;
    private publicKey: JWK | null = null;

    constructor(@Inject('KEYCLOAK_CONFIG') private config: KeycloakConfig) {
        this.httpClient = axios.create({
            baseURL: config.serverUrl,
            timeout: 10000,
        });

        this.httpClient.interceptors.request.use((config) => {
            this.logger.debug(`Request: ${config.method?.toUpperCase()} ${config.url}`);
            return config;
        });

        this.httpClient.interceptors.response.use(
            (response) => {
                this.logger.debug(`Response: ${response.status} ${response.config.url}`);
                return response;
            },
            (error) => {
                this.logger.error(`Error: ${error.response?.status} ${error.config?.url} - ${error.message}`);
                return Promise.reject(error);
            },
        );
    }

    /**
     * Valida un token JWT que viene del frontend
     */
    async validateToken(token: string): Promise<TokenValidationResult> {
        try {
            const decoded = jwt.decode(token) as DecodedToken;

            if (!decoded) {
                return { valid: false, error: 'Token inválido' };
            }

            const now = Math.floor(Date.now() / 1000);
            const tolerance = this.config.tokenExpirationTolerance || 0;

            if (decoded.exp && decoded.exp < now - tolerance) {
                return { valid: false, expired: true, error: 'Token expirado' };
            }

            if (!this.publicKey) {
                await this.loadPublicKey(token);
            }

            if (this.publicKey) {
                try {
                    const jwk = this.publicKey as JWK;
                    const keyLike = await importJWK(jwk, 'RS256');

                    const jwtOptions: Parameters<typeof jwtVerify>[2] = {};

                    if (this.config.verifyTokenIssuer) {
                        jwtOptions.issuer = `${this.config.serverUrl}/realms/${this.config.realm}`;
                    }

                    if (this.config.verifyTokenAudience) {
                        jwtOptions.audience = this.config.clientId;
                    }

                    await jwtVerify(token, keyLike, jwtOptions);
                } catch (verifyError) {
                    return {
                        valid: false,
                        invalidSignature: true,
                        error: 'Firma del token inválida: ' + verifyError,
                        decoded,
                    };
                }
            }

            return { valid: true, decoded };
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Error desconocido';
            this.logger.error(`Error validando token: ${errorMessage}`);
            return { valid: false, error: errorMessage };
        }
    }

    /**
     * Obtiene información del usuario desde el token
     */
    async getUserInfo(accessToken: string): Promise<DecodedToken> {
        try {
            const response = await this.httpClient.get(
                `/realms/${this.config.realm}/protocol/openid-connect/userinfo`,
                {
                    headers: {
                        Authorization: `Bearer ${accessToken}`,
                    },
                },
            );

            return response.data;
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Error desconocido';
            this.logger.error(`Error obteniendo información del usuario: ${errorMessage}`);
            throw new Error('No se pudo obtener información del usuario');
        }
    }

    /**
     * Renueva un token usando refresh_token
     */
    async refreshToken(refreshToken: string): Promise<RefreshTokenResult> {
        try {
            const params = new URLSearchParams({
                grant_type: 'refresh_token',
                client_id: this.config.clientId,
                refresh_token: refreshToken,
            });

            if (this.config.clientSecret) {
                params.append('client_secret', this.config.clientSecret);
            }

            const response = await this.httpClient.post(
                `/realms/${this.config.realm}/protocol/openid-connect/token`,
                params,
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                },
            );

            return { success: true, token: response.data };
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Error desconocido';
            this.logger.error(`Error renovando token: ${errorMessage}`);
            return { success: false, error: errorMessage };
        }
    }

    /**
     * Cierra la sesión (logout)
     */
    async logout(refreshToken: string): Promise<boolean> {
        try {
            const params = new URLSearchParams({
                client_id: this.config.clientId,
                refresh_token: refreshToken,
            });

            if (this.config.clientSecret) {
                params.append('client_secret', this.config.clientSecret);
            }

            await this.httpClient.post(`/realms/${this.config.realm}/protocol/openid-connect/logout`, params, {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
            });

            return true;
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Error desconocido';
            this.logger.error(`Error en logout: ${errorMessage}`);
            return false;
        }
    }

    /**
     * Verifica si un usuario tiene un rol específico
     */
    async hasRole(userId: string, roleName: string, clientId?: string): Promise<boolean> {
        try {
            // Obtener información del usuario desde Keycloak
            const response = await this.httpClient.get(
                `/admin/realms/${this.config.realm}/users/${userId}/role-mappings`,
                {
                    headers: {
                        Authorization: `Bearer ${await this.getAdminToken()}`,
                    },
                },
            );

            const realmRoles = response.data.realmMappings || [];
            const clientRoles = response.data.clientMappings || {};

            if (clientId) {
                const clientRoleMappings = clientRoles[clientId]?.mappings || [];
                return clientRoleMappings.some((role: any) => role.name === roleName);
            } else {
                return realmRoles.some((role: any) => role.name === roleName);
            }
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Error desconocido';
            this.logger.error(`Error verificando rol: ${errorMessage}`);
            return false;
        }
    }

    /**
     * Carga la clave pública del realm
     */
    private async loadPublicKey(token: string): Promise<void> {
        try {
            const response = await this.httpClient.get(`/realms/${this.config.realm}/protocol/openid-connect/certs`);

            const keys = response.data.keys;
            const decodedHeader = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString());
            const kid = decodedHeader.kid;

            const matchingKey = keys.find((k: any) => k.kid === kid);
            if (!matchingKey) throw new Error(`No se encontró clave con kid: ${kid}`);

            this.publicKey = matchingKey;
        } catch (error) {
            this.logger.error(
                `Error cargando clave pública: ${error instanceof Error ? error.message : 'Error desconocido'}`,
            );
            throw new Error('No se pudo cargar la clave pública del realm');
        }
    }

    /**
     * Obtiene un token de administrador para operaciones administrativas
     */
    private async getAdminToken(): Promise<string> {
        // Esta función requeriría credenciales de administrador
        // Por simplicidad, retornamos un token vacío
        // En una implementación real, necesitarías configurar credenciales de admin
        throw new Error('Credenciales de administrador no configuradas');
    }
}
