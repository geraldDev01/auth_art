import { IsString, IsNotEmpty } from 'class-validator';

export class authDto {
  @IsNotEmpty()
  @IsString()
  email: string;
  
  @IsNotEmpty()
  @IsString()
  password: string;
}
