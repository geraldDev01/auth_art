import { Body, ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { authDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async signupLocal(@Body() dto: authDto): Promise<Tokens> {
    const { email, password } = dto;
    const hash = await this.hashData(password);

    const newUser = await this.prisma.user.create({
      data: {
        email,
        hash,
      },
    });
    const tokens = await this.getTokens(newUser.id, newUser.email);
    //we update in database the refresh token
    await this.updateRtHash(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async updateRtHash(userId: number, rt: string) {
    const rtHashed = await this.hashData(rt);

    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRTK: rtHashed,
      },
    });
  }

  async signinLocal(@Body() dto: authDto): Promise<Tokens> {
    const { email, password } = dto;
    const user = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });
    if (!user) throw new ForbiddenException('Access denied');

    const passwordCheck = await bcrypt.compare(password, user.hash);

    if (!passwordCheck) throw new ForbiddenException('Access denied');

    const tokens = await this.getTokens(user.id, user.email);
    //we update in database the refresh token
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async logout(userId: number) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRTK: {
          not: null,
        },
      },
      data: {
        hashedRTK: null,
      },
    });
  }

  async refreshTokens(userId: number, rt: string): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user) throw new ForbiddenException('Access denied');

    const rtCheck = await bcrypt.compare(rt, user.hashedRTK);

    if (!rtCheck) throw new ForbiddenException('Access denied');

    const tokens = await this.getTokens(user.id, user.email);
    //we update in database the refresh token
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'access_token_secret',
          expiresIn: 60 * 15,
        },
      ),

      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'refresh_token_secret',
          expiresIn: 60 * 15,
        },
      ),
    ]);
    return {
      access_token: at,
      refresh_token: rt,
    };
  }
}
