export async function GET({ request }: { request: Request }) {
  return Response.json(await load(request.url))
}
declare function load(url: string): Promise<unknown>
