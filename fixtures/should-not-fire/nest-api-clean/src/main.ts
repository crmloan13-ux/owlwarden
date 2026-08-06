import { NestFactory } from '@nestjs/core'
import helmet from 'helmet'

import { AppModule } from './app.module'

async function bootstrap() {
  const app = await NestFactory.create(AppModule)
  app.use(helmet())
  app.enableCors({
    origin: ['https://app.example.com'],
    credentials: true,
  })
  await app.listen(3000)
}

void bootstrap()
