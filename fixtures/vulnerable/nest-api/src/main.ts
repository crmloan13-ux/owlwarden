// FIXTURE: deliberately vulnerable. Expected findings:
//   security-headers-missing — the bootstrap never registers helmet.
import { NestFactory } from '@nestjs/core'

import { AppModule } from './app.module'

async function bootstrap() {
  const app = await NestFactory.create(AppModule)
  await app.listen(3000)
}

void bootstrap()
