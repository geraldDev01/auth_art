import { Body, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { authDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService
    ) {}

  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

//   async validateUser(username: string, pass: string): Promise<any> {
//     const user = await this.prisma.us.findOne(username);
//     if (user && user.password === pass) {
//       const { password, ...result } = user;
//       return result;
//     }
//     return null;
//   }


  async signupLocal(@Body() dto: authDto): Promise<Tokens>{
    const { email, password } = dto;
    const hash = await this.hashData(password);

    const newUser = this.prisma.user.create({
      data: {
        email,
        hash,
      },
    });
  }

  signinLocal() {}

  logout() {}

  refresh() {}
}
