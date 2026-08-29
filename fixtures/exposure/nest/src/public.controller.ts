import { Controller, Get } from '@nestjs/common'

@Controller('public')
export class PublicController {
  @Get('reports')
  reports() {
    return load()
  }
}
declare function load(): Promise<unknown>
