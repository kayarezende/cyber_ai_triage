// Wk-9 placeholder. Real Entra ID OIDC sign-in lands wk-11.
//
// In dev, `DEV_BYPASS_AUTH=1` skips this page entirely (the middleware
// passes through without redirect). Hitting `/login` directly during dev
// confirms the bypass flag is set.

export default function LoginPage() {
  return (
    <div className="mx-auto max-w-xl rounded-md border border-zinc-800 bg-zinc-900 p-6">
      <h1 className="text-lg font-semibold text-zinc-100">Sign in</h1>
      <p className="mt-2 text-sm text-zinc-400">
        Entra ID single sign-on lands in wk-11. For local development set{" "}
        <code className="rounded bg-zinc-800 px-1.5 py-0.5 text-zinc-200">
          DEV_BYPASS_AUTH=1
        </code>{" "}
        in your environment and refresh.
      </p>
    </div>
  );
}
