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

const ALLOWED_IMPORT_HOSTS = new Set(['files.partner.com'])

function safeRedirect(target: unknown, base: string, fallback = '/'): string {
  if (typeof target !== 'string') return fallback
  try {
    const resolved = new URL(target, base)
    return resolved.origin === new URL(base).origin
      ? resolved.pathname + resolved.search
      : fallback
  } catch {
    return fallback
  }
}

function assertAllowedUrl(raw: unknown): URL {
  const url = new URL(String(raw))
  if (url.protocol !== 'https:' || !ALLOWED_IMPORT_HOSTS.has(url.hostname)) {
    throw new InternalServerErrorException('source not allowed')
  }
  return url
}

@Controller('users')
export class UsersController {
  private readonly logger = new Logger(UsersController.name)
  private readonly pool = {
    query: async (_sql: string, _params: unknown[]) => [{ id: '1' }],
  }

  @Get()
  findAll() {
    try {
      return this.load()
    } catch (err) {
      this.logger.error('findAll failed', err instanceof Error ? err.stack : err)
      throw new InternalServerErrorException()
    }
  }

  @Post('login')
  async login(
    @Body() body: { email?: string; password?: string; accessToken?: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    // Logging that a caller supplied a token, not the token itself.
    this.logger.log({ hasAccessToken: Boolean(body.accessToken) })

    const rows = await this.pool.query(
      'SELECT id, role FROM users WHERE email = $1',
      [body.email],
    )

    res.cookie('session', rows[0]?.id ?? 'anon', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
    })

    return { ok: true }
  }

  @Get('go')
  go(@Query('next') next: string, @Res() res: Response) {
    res.redirect(safeRedirect(next, 'https://app.example.com'))
  }

  @Get('go2')
  goHeader(@Query('next') next: string, @Res() res: Response) {
    res.setHeader('Location', safeRedirect(next, 'https://app.example.com'))
    res.status(302).end()
  }

  @Post('import')
  async importRemote(@Body() body: { sourceUrl?: string }) {
    const url = assertAllowedUrl(body.sourceUrl)
    const upstream = await fetch(url, { redirect: 'error' })
    return upstream.json()
  }

  @Post('import2')
  async importRemoteViaAxios(@Body() body: { callerUrl?: string }) {
    const url = assertAllowedUrl(body.callerUrl)
    const upstream = await axios.get(url.toString(), { maxRedirects: 0 })
    return upstream.data
  }

  private load(): string[] {
    return ['ada']
  }
}
