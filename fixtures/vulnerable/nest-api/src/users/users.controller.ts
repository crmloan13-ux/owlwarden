// FIXTURE: deliberately vulnerable. Expected findings:
//   stack-trace-leak — the caught error's stack is put into the exception body.
//   sensitive-data-logged — a password field written through the Nest logger.
import { Controller, Get, InternalServerErrorException, Logger, Post, Body } from '@nestjs/common'

@Controller('users')
export class UsersController {
  private readonly logger = new Logger(UsersController.name)

  @Get()
  findAll() {
    try {
      return this.load()
    } catch (err) {
      throw new InternalServerErrorException({
        message: 'could not load users',
        stack: err.stack,
      })
    }
  }

  @Post('login')
  login(@Body() body: { password: string }) {
    // sensitive-data-logged
    this.logger.log({ password: body.password })
    return { ok: true }
  }

  private load(): string[] {
    return ['ada']
  }
}
