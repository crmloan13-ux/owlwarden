// FIXTURE: hardcoded-secret — Stripe live key prefix.
const STRIPE_KEY = 'sk_live_51Nx-AbCdEfGhIjKlMnOpQrStUvWx'

export async function charge(amountCents: number) {
  return fetch('https://api.stripe.com/v1/charges', {
    method: 'POST',
    headers: { Authorization: `Bearer ${STRIPE_KEY}` },
    body: new URLSearchParams({ amount: String(amountCents) }),
  })
}
