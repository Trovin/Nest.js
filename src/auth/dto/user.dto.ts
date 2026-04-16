
import { IsEmail, MinLength, IsOptional, IsString } from 'class-validator';

export class CreateUserDto {
    @IsEmail()
    email: string;

    @MinLength(6)
    password: string;

    @IsOptional()
    @IsString()
    name?: string;
}