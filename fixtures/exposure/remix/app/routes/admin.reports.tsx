import { requireUserId } from '../utils/session.server'

export async function loader({ request }: { request: Request }) {
  await requireUserId(request)
  return load(request.url)
}
declare function load(url: string): Promise<unknown>
