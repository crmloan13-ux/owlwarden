// Correct code that a naive `.stack` rule would flag. Each case is here because
// getting it wrong is the difference between a tool people keep and one they
// uninstall.
import { NextResponse } from 'next/server'

interface Project {
  name: string
  /** The technology stack. Nothing to do with error traces. */
  stack: string[]
}

const project: Project = { name: 'owlwarden', stack: ['rust', 'typescript'] }

const logger = {
  error(message: string, detail?: unknown) {
    console.error(message, detail)
  },
}

export async function GET() {
  // 1. A `.stack` property that is a technology list, in a response body.
  return NextResponse.json({ project: project.stack })
}

export async function POST(request: Request) {
  try {
    const body = await request.json()
    // 4. The word "password" in a string is product copy, not a secret.
    console.info('password reset email queued')
    // 5. A name that merely *contains* a sensitive word is not the secret.
    console.info({ passwordLength: typeof body?.password === 'string' ? body.password.length : 0 })
    return NextResponse.json({ received: body })
  } catch (err) {
    // 2. A logger call shaped like a response call. Not a sink.
    logger.error('POST /api/profile failed', err instanceof Error ? err.stack : err)

    // 3. The stack captured into a local variable and then *not* returned.
    const trace = err instanceof Error ? err.stack : undefined
    if (process.env.NODE_ENV === 'development' && trace) {
      console.debug(trace)
    }

    return NextResponse.json({ error: 'Bad Request' }, { status: 400 })
  }
}
