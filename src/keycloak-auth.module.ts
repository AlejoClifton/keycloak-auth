import { Module, DynamicModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { KeycloakConfig } from './interfaces/keycloak-config.interface';
import { KeycloakAuthService } from './keycloak-auth.service';
import { KeycloakAuthGuard } from './guards/keycloak-auth.guard';

@Module({})
export class KeycloakAuthModule {
    static forRootFromEnv(): DynamicModule {
        return {
            module: KeycloakAuthModule,
            imports: [ConfigModule],
            providers: [
                {
                    provide: 'KEYCLOAK_CONFIG',
                    useFactory: (configService: ConfigService): KeycloakConfig => ({
                        serverUrl: configService.get<string>('KEYCLOAK_SERVER_URL', 'http://localhost:8080'),
                        realm: configService.get<string>('KEYCLOAK_REALM', 'my-realm'),
                        clientId: configService.get<string>('KEYCLOAK_CLIENT_ID', 'backend'),
                        clientSecret: configService.get<string>('KEYCLOAK_CLIENT_SECRET'),
                        verifyTokenIssuer: configService.get<boolean>('KEYCLOAK_VERIFY_ISSUER', true),
                        verifyTokenAudience: configService.get<boolean>('KEYCLOAK_VERIFY_AUDIENCE', true),
                    }),
                    inject: [ConfigService],
                },
                KeycloakAuthService,
                KeycloakAuthGuard,
            ],
            exports: [KeycloakAuthService, KeycloakAuthGuard],
        };
    }
}
