export interface KeycloakConfig {
  serverUrl: string; // http://localhost:8080
  realm: string; // the-name-of-the-realm
  clientId: string; // the-name-of-the-client
  clientSecret?: string; // opcional para clientes públicos
  publicKey?: string; // clave pública del realm para validar JWT
  verifyTokenAudience?: boolean; // verificar audience del token
  verifyTokenIssuer?: boolean; // verificar issuer del token
  tokenExpirationTolerance?: number; // tolerancia en segundos para expiración
}

export interface DecodedToken {
  sub: string; // subject (user ID)
  iss: string; // issuer
  aud: string | string[]; // audience
  exp: number; // expiration time
  iat: number; // issued at
  jti?: string; // JWT ID
  azp?: string; // authorized party
  scope?: string; // scopes
  realm_access?: {
    roles: string[];
  };
  resource_access?: {
    [clientId: string]: {
      roles: string[];
    };
  };
  preferred_username?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
}

export interface TokenValidationResult {
  valid: boolean;
  decoded?: DecodedToken;
  error?: string;
  expired?: boolean;
  invalidSignature?: boolean;
  invalidAudience?: boolean;
  invalidIssuer?: boolean;
}

export interface RefreshTokenResult {
  success: boolean;
  token?: {
    access_token: string;
    refresh_token?: string;
    token_type: string;
    expires_in: number;
    scope?: string;
    id_token?: string;
  };
  error?: string;
} 