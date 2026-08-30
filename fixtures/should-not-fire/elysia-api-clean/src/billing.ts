// Read the way it should be read: not a literal, so nothing to report.
const stripeKey = process.env.STRIPE_KEY ?? ''

export async function charge(amountCents: number) {
  return fetch('https://api.stripe.com/v1/charges', {
    method: 'POST',
    headers: { Authorization: `Bearer ${stripeKey}` },
    body: new URLSearchParams({ amount: String(amountCents) }),
  })
}
