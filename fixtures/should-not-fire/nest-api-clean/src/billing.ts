const STRIPE_KEY = process.env.STRIPE_KEY ?? ''

export async function charge(amountCents: number) {
  return fetch('https://api.stripe.com/v1/charges', {
    method: 'POST',
    headers: { Authorization: `Bearer ${STRIPE_KEY}` },
    body: new URLSearchParams({ amount: String(amountCents) }),
  })
}
