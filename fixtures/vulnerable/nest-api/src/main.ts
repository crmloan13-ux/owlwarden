// FIXTURE: deliberately vulnerable. Expected findings:
//   security-headers-missing — the bootstrap never registers helmet.
//   cors-permissive — enableCors reflects any origin with credentials.
import { NestFactory } from '@nestjs/core'

import { AppModule } from './app.module'

async function bootstrap() {
  const app = await NestFactory.create(AppModule)
  app.enableCors({ origin: true, credentials: true })
  await app.listen(3000)
}

void bootstrap()
