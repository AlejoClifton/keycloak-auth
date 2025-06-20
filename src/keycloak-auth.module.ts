import { Module, DynamicModule, Provider } from '@nestjs/common';
import { KeycloakAuthService } from './keycloak-auth.service';
import { KeycloakAuthGuard } from './guards/keycloak-auth.guard';
import { KeycloakConfig } from './interfaces/keycloak-config.interface';

export interface KeycloakAuthModuleOptions {
  config: KeycloakConfig;
}

@Module({})
export class KeycloakAuthModule {
  static forRoot(options: KeycloakAuthModuleOptions): DynamicModule {
    const configProvider: Provider = {
      provide: 'KEYCLOAK_CONFIG',
      useValue: options.config,
    };

    return {
      module: KeycloakAuthModule,
      providers: [
        configProvider, 
        KeycloakAuthService,
        KeycloakAuthGuard
      ],
      exports: [KeycloakAuthService, KeycloakAuthGuard],
      global: true,
    };
  }

  static forRootAsync(options: {
    useFactory: (...args: any[]) => Promise<KeycloakConfig> | KeycloakConfig;
    inject?: any[];
  }): DynamicModule {
    const configProvider: Provider = {
      provide: 'KEYCLOAK_CONFIG',
      useFactory: options.useFactory,
      inject: options.inject || [],
    };

    return {
      module: KeycloakAuthModule,
      providers: [
        configProvider, 
        KeycloakAuthService,
        KeycloakAuthGuard
      ],
      exports: [KeycloakAuthService, KeycloakAuthGuard],
      global: true,
    };
  }
} 