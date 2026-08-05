// FIXTURE: deliberately vulnerable. Expected findings:
//   stack-trace-leak — the caught error's stack is put into the exception body.
import { Controller, Get, InternalServerErrorException } from '@nestjs/common'

@Controller('users')
export class UsersController {
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

  private load(): string[] {
    return ['ada']
  }
}
