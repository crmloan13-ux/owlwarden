const STRIPE_KEY = process.env.STRIPE_KEY ?? ''

export default defineEventHandler(async () => {
  return fetch('https://api.stripe.com/v1/charges', {
    method: 'POST',
    headers: { Authorization: `Bearer ${STRIPE_KEY}` },
    body: new URLSearchParams({ amount: '100' }),
  })
})
