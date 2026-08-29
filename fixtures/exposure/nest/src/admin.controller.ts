import { Controller, Get, UseGuards } from '@nestjs/common'
import { AuthGuard } from '@nestjs/passport'

@Controller('admin')
@UseGuards(AuthGuard('jwt'))
export class AdminController {
  @Get('reports')
  reports() {
    return load()
  }
}
declare function load(): Promise<unknown>
