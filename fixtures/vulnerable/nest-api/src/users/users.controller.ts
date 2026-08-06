// FIXTURE: deliberately vulnerable. Expected findings:
//   stack-trace-leak — the caught error's stack is put into the exception body.
//   sensitive-data-logged — a password field written through the Nest logger.
//   sql-injection — email interpolated into this.pool.query.
//   insecure-cookie — res.cookie without protective attributes.
//   ssrf / open-redirect — caller-controlled fetch and redirect.
import {
  Body,
  Controller,
  Get,
  InternalServerErrorException,
  Logger,
  Post,
  Query,
  Res,
} from '@nestjs/common'
import type { Response } from 'express'

@Controller('users')
export class UsersController {
  private readonly logger = new Logger(UsersController.name)
  // Named so sql-injection's QUERY_OBJECTS accepts the root (`this`).
  private readonly pool = {
    query: async (_sql: string) => [{ id: '1' }],
  }

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
  async login(
    @Body() body: { email?: string; password?: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    // sensitive-data-logged
    this.logger.log({ password: body.password })

    // sql-injection
    const rows = await this.pool.query(
      `SELECT id, role FROM users WHERE email = '${body.email}'`,
    )

    // insecure-cookie
    res.cookie('session', rows[0]?.id ?? 'anon')

    return { ok: true }
  }

  @Get('go')
  go(@Query() query: { next?: string }, @Res() res: Response) {
    // open-redirect — `query` is a universal request-source name.
    res.redirect(query.next as string)
  }

  @Post('import')
  async importRemote(@Body() body: { sourceUrl?: string }) {
    // ssrf
    const upstream = await fetch(body.sourceUrl as string)
    return upstream.json()
  }

  private load(): string[] {
    return ['ada']
  }
}
