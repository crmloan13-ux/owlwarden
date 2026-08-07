// FIXTURE: deliberately vulnerable. Expected findings:
//   stack-trace-leak — the caught error's stack is put into the exception body.
//   sensitive-data-logged — a password field and an access token written
//   through the Nest logger.
//   sql-injection — email interpolated into this.pool.query.
//   insecure-cookie — res.cookie without protective attributes.
//   ssrf / open-redirect — caller-controlled fetch/axios and redirect()/header.
import axios from 'axios'
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
    @Body() body: { email?: string; password?: string; accessToken?: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    // sensitive-data-logged
    this.logger.log({ password: body.password })

    // sensitive-data-logged: an access token, logged the same way.
    this.logger.log({ accessToken: body.accessToken })

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

  @Get('go2')
  goHeader(@Query() query: { next?: string }, @Res() res: Response) {
    // open-redirect: a hand-rolled Location header instead of res.redirect().
    res.setHeader('Location', query.next as string)
    res.status(302).end()
  }

  @Post('import')
  async importRemote(@Body() body: { sourceUrl?: string }) {
    // ssrf
    const upstream = await fetch(body.sourceUrl as string)
    return upstream.json()
  }

  @Post('import2')
  async importRemoteViaAxios(@Body() body: { callerUrl?: string }) {
    // ssrf: axios reaches a second caller-controlled host.
    const upstream = await axios.get(body.callerUrl as string)
    return upstream.data
  }

  private load(): string[] {
    return ['ada']
  }
}
