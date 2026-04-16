import {
    Injectable,
    ConflictException,
    UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

type User = {
    id: number;
    email: string;
    passwordHash: string;
    refreshTokenHash: string | null;
};

@Injectable()
export class AuthService {
    private users: User[] = [];
    private nextId = 1;

    constructor(private readonly jwtService: JwtService) {}

    async register(email: string, password: string) {
        const existingUser = this.users.find((user) => user.email === email);

        if (existingUser) {
            throw new ConflictException('User already exists');
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const user: User = {
            id: this.nextId++,
            email,
            passwordHash,
            refreshTokenHash: null,
        };

        this.users.push(user);

        const tokens = await this.generateTokens(user.id, user.email);
        await this.saveRefreshTokenHash(user.id, tokens.refreshToken);

        return {
            user: {
                id: user.id,
                email: user.email,
            },
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
        };
    }

    async login(email: string, password: string) {
        const user = this.users.find((user) => user.email === email);

        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const isPasswordMatched = await bcrypt.compare(password, user.passwordHash);

        if (!isPasswordMatched) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const tokens = await this.generateTokens(user.id, user.email);
        await this.saveRefreshTokenHash(user.id, tokens.refreshToken);

        return {
            user: {
                id: user.id,
                email: user.email,
            },
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
        };
    }

    async refresh(refreshToken: string) {
        let payload: { sub: number; email: string };

        try {
            payload = await this.jwtService.verifyAsync(refreshToken, {
                secret: 'REFRESH_SECRET',
            });
        } catch {
            throw new UnauthorizedException('Invalid refresh token');
        }

        const user = this.users.find((user) => user.id === payload.sub);

        if (!user || !user.refreshTokenHash) {
            throw new UnauthorizedException('Access denied');
        }

        const isRefreshMatched = await bcrypt.compare(
            refreshToken,
            user.refreshTokenHash,
        );

        if (!isRefreshMatched) {
            throw new UnauthorizedException('Access denied');
        }

        const tokens = await this.generateTokens(user.id, user.email);
        await this.saveRefreshTokenHash(user.id, tokens.refreshToken);

        return {
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
        };
    }

    async logout(userId: number) {
        const user = this.users.find((user) => user.id === userId);

        if (user) {
            user.refreshTokenHash = null;
        }

        return { message: 'Logged out' };
    }

    private async generateTokens(userId: number, email: string) {
        const payload = { sub: userId, email };

        const [accessToken, refreshToken] = await Promise.all([
            this.jwtService.signAsync(payload, {
                secret: 'ACCESS_SECRET',
                expiresIn: '1h',
            }),
            this.jwtService.signAsync(payload, {
                secret: 'REFRESH_SECRET',
                expiresIn: '1d',
            }),
        ]);

        return {
            accessToken,
            refreshToken,
        };
    }

    private async saveRefreshTokenHash(userId: number, refreshToken: string) {
        const user = this.users.find((user) => user.id === userId);

        if (!user) return;

        user.refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    }
}