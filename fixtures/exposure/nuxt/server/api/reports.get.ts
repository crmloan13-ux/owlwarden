export default defineEventHandler(async (event) => load(event))
declare function load(event: unknown): Promise<unknown>
