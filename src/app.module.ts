import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { AppController } from "./app.controller";
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [
      AuthModule,
      ConfigModule.forRoot({
          isGlobal: true
      })
  ],
  controllers: [AppController],
  providers: []
})
export class AppModule {}
