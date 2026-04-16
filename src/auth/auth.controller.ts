import {
    Body,
    Controller,
    Post,
    Req,
    Res,
    UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import type { Request, Response } from 'express';
import { RegisterDto } from './dto/register.dto';
import { CreateUserDto } from './dto/user.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('register')
    async register(
        @Body() body: CreateUserDto,
        @Res({ passthrough: true }) res: Response,
    ) {
        const result = await this.authService.register(
            body.email,
            body.password,
        );

        this.setRefreshCookie(res, result.refreshToken);

        return {
            user: result.user,
            accessToken: result.accessToken,
        };
    }

    @Post('login')
    async login(
        @Body() body: CreateUserDto,
        @Res({ passthrough: true }) res: Response,
    ) {
        const result = await this.authService.login(
            body.email,
            body.password,
        );

        this.setRefreshCookie(res, result.refreshToken);

        return {
            user: result.user,
            accessToken: result.accessToken,
        };
    }

    @Post('refresh')
    async refresh(
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ) {
        const refreshToken = req.cookies?.refreshToken;

        if (!refreshToken) {
            throw new UnauthorizedException('No refresh token');
        }

        const result = await this.authService.refresh(refreshToken);

        this.setRefreshCookie(res, result.refreshToken);

        return {
            accessToken: result.accessToken,
        };
    }

    @Post('logout')
    async logout(
        @Body() body: { userId: number },
        @Res({ passthrough: true }) res: Response,
    ) {
        await this.authService.logout(body.userId);

        res.clearCookie('refreshToken');

        return { message: 'Logged out' };
    }

    private setRefreshCookie(res: Response, token: string) {
        res.cookie('refreshToken', token, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/',
        });
    }
}