import {
  Controller,
  Get,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common'

@Controller('users')
export class UsersController {
  private readonly logger = new Logger(UsersController.name)

  @Get()
  findAll() {
    try {
      return this.load()
    } catch (err) {
      this.logger.error('findAll failed', err instanceof Error ? err.stack : err)
      throw new InternalServerErrorException()
    }
  }

  private load(): string[] {
    return ['ada']
  }
}
