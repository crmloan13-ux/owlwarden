// FIXTURE: deliberately vulnerable. Expected findings:
//   stack-trace-leak at the `err.stack` inside the NextResponse.json body.
import { NextResponse } from 'next/server'

import { listUsers } from '../../lib/users'

export async function GET() {
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
