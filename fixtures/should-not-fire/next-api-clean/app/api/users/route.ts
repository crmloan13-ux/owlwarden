// The vulnerable fixture, done right: the stack goes to the server log, the
// client gets a generic message.
import { NextResponse } from 'next/server'

import { listUsers } from '../../lib/users'

export async function GET() {
  try {
    const users = await listUsers()
    return NextResponse.json({ users })
  } catch (err) {
    // Logging a stack trace server-side is correct. A rule that flags this
    // teaches people to stop logging, which is worse than the bug it prevents.
    console.error('GET /api/users failed', err instanceof Error ? err.stack : err)
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 })
  }
}
