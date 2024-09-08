import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';

type JwtPayload = {
  sub: string;
  email: string;
};

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: 'refresh_token_secret',
      passReqToCallback: true,
    });
  }
  validate(req: Request, payload: JwtPayload) {
    const refreshToken = req.get('authorization').replace('Bearer ', '').trim();

    return {
      ...payload,
      refreshToken,
    };
  }
}
