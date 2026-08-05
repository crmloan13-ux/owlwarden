// Support file for the fixture. Nothing here should produce a finding.
export interface User {
  id: string
  email: string
}

export async function listUsers(): Promise<User[]> {
  return [{ id: '1', email: 'ada@example.com' }]
}
