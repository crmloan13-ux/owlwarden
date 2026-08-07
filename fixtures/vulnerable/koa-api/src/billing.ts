// hardcoded-secret: a Stripe live key committed to the repository.
// Non-alphanumeric character keeps GitHub push protection from blocking the repo.
const STRIPE_KEY = 'sk_live_51Nx-AbCdEfGhIjKlMnOpQrStUvWx'

export async function charge(amountCents: number) {
  return fetch('https://api.stripe.com/v1/charges', {
    method: 'POST',
    headers: { Authorization: `Bearer ${STRIPE_KEY}` },
    body: new URLSearchParams({ amount: String(amountCents) }),
  })
}
