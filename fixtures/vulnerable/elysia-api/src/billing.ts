// hardcoded-secret: a Stripe live key committed to the repository. Recognised
// by its prefix rather than by the variable name, so renaming would not hide
// it.
//
// The suffix is not pure alphanumeric, and must stay that way. GitHub's push
// protection matches `sk_live_` followed by 24 or more alphanumerics, so a
// fully realistic key here makes the repository unpushable for us and for
// anyone who forks it. One non-alphanumeric character drops us below that
// threshold while staying above ours, which needs only the prefix and nine
// more characters. Tidying this into a "proper" key will block your push.
const STRIPE_KEY = 'sk_live_51Nx-AbCdEfGhIjKlMnOpQrStUvWx'

export async function charge(amountCents: number) {
  return fetch('https://api.stripe.com/v1/charges', {
    method: 'POST',
    headers: { Authorization: `Bearer ${STRIPE_KEY}` },
    body: new URLSearchParams({ amount: String(amountCents) }),
  })
}
