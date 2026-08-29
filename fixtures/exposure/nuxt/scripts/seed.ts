// internal: a build-time seed. Nothing serves it.
export async function seed() {
  const rows = await query(`SELECT * FROM users`)
  return rows
}
declare function query(sql: string): Promise<unknown[]>
