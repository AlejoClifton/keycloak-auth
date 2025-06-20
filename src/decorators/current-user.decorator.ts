import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { DecodedToken } from '@/interfaces/keycloak-config.interface';

export const CurrentUser = createParamDecorator(
  (data: keyof DecodedToken | undefined, ctx: ExecutionContext): DecodedToken | any => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    return data ? user?.[data] : user;
  },
); 