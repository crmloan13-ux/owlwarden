// FIXTURE: deliberately vulnerable. Expected findings:
//   stack-trace-leak at the `err.stack` inside the NextResponse.json body.
//   sensitive-data-logged at the authorization header written to console.
import { NextResponse } from 'next/server'

import { listUsers } from '../../lib/users'

export async function GET(request: Request) {
  // sensitive-data-logged: the Authorization header lands in the log aggregator.
  console.info({ authorization: request.headers.get('authorization') })
  try {
    const users = await listUsers()
    return NextResponse.json({ users })
  } catch (err) {
    return NextResponse.json(
      { error: err.stack },
      { status: 500 }
    )
  }
}
