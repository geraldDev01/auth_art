import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { authDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService){}

    @Post('/local/signup')
    signupLocal(@Body() dto: authDto): Promise<Tokens>{
        this.authService.signupLocal(dto)
    }

    @Post('/local/signin')
    signinLocal(){
        this.authService.signinLocal()
    }

    @Post('/logout')
    logout(){
        this.authService.logout()
    }

    @Post('/refresh')
    refresh(){
        this.authService.refresh()
    }
    

}
