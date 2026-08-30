export async function loader({ request }: { request: Request }) {
  return load(request.url)
}
declare function load(url: string): Promise<unknown>
