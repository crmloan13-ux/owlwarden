export interface User {
  id: string
  email: string
}

export async function listUsers(): Promise<User[]> {
  return [{ id: '1', email: 'ada@example.com' }]
}
