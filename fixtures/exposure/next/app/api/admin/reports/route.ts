export async function GET(request: Request) {
  return Response.json(await load(request.url))
}
declare function load(url: string): Promise<unknown>
