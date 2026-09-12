"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, money, parsePaise, RequestError } from "../lib/api";

type User = { id: string; name: string; email: string; role: "user" | "admin" };
type Transfer = {
  id: string;
  sender_id: string;
  recipient_id: string;
  amount: string;
  note: string;
  created_at: string;
  sender_name?: string;
  recipient_name?: string;
};
type Ticket = {
  id: string;
  subject: string;
  status: string;
  created_at: string;
};
type Comment = {
  id: string;
  name: string;
  role: string;
  body: string;
  created_at: string;
};
type AdminRow = {
  id: string;
  name?: string;
  email?: string;
  role?: string;
  subject?: string;
  status?: string;
  amount?: string;
  event?: string;
  created_at: string;
};
type Detection = {
  id: string;
  rule: string;
  title: string;
  severity: "high" | "medium" | "low";
  subject: string;
  count: number;
  last_seen: string;
  window_minutes: number;
  threshold: number;
  response: string;
};
const date = (value: string) =>
  new Date(value).toLocaleString("en-IN", {
    dateStyle: "medium",
    timeStyle: "short",
  });
const text = (error: unknown) =>
  error instanceof Error
    ? error.message
    : "Something went wrong. Please try again.";
const publicRoutes = ["login", "register", "forgot-password", "reset-password"];
function Field({
  label,
  ...props
}: React.InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  return (
    <label className="field">
      <span>{label}</span>
      <input {...props} />
    </label>
  );
}
function Notice({
  children,
  error = false,
}: {
  children: React.ReactNode;
  error?: boolean;
}) {
  return (
    <p
      className={error ? "notice error" : "notice"}
      role={error ? "alert" : "status"}
    >
      {children}
    </p>
  );
}

function AuthForm({ path }: { path: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const titles: Record<string, string> = {
    login: "Welcome back.",
    register: "A wallet of your own.",
    "forgot-password": "Let’s get you back in.",
    "reset-password": "Choose a new password.",
  };
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    const values = Object.fromEntries(new FormData(event.currentTarget));
    try {
      if (path === "reset-password")
        values.token =
          new URLSearchParams(window.location.hash.slice(1)).get("token") ?? "";
      const result = await api<{ message?: string }>(`/auth/${path}`, {
        method: "POST",
        body: JSON.stringify(values),
      });
      if (path === "login") router.push("/");
      else {
        setMessage(result.message ?? "Done.");
        if (path === "reset-password")
          window.history.replaceState(null, "", "/reset-password");
      }
    } catch (error) {
      setError(text(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="auth-layout">
      <section className="auth-intro">
        <div className="brand-mark" aria-hidden="true">
          S
        </div>
        <h1>
          Your money.
          <br />A little simpler.
        </h1>
        <p>
          A clear view of your balance, easy transfers, and support when you
          need it.
        </p>
        <span className="demo">Demo — fake funds</span>
      </section>
      <section className="auth-form">
        <h2>{titles[path]}</h2>
        <p className="muted">
          {path === "login"
            ? "Sign in to your SecureWallet account."
            : path === "register"
              ? "Create your account to get started."
              : "Follow the steps to securely recover your account."}
        </p>
        <form onSubmit={submit}>
          {path === "register" && (
            <Field
              label="Full name"
              name="name"
              autoComplete="name"
              maxLength={80}
              required
            />
          )}
          {path !== "reset-password" && (
            <Field
              label="Email address"
              name="email"
              type="email"
              autoComplete="email"
              maxLength={254}
              required
            />
          )}
          {path !== "forgot-password" && (
            <Field
              label={path === "reset-password" ? "New password" : "Password"}
              name={path === "reset-password" ? "newPassword" : "password"}
              type="password"
              autoComplete={
                path === "login" ? "current-password" : "new-password"
              }
              minLength={path === "login" ? 1 : 12}
              maxLength={128}
              required
            />
          )}
          {(path === "register" || path === "reset-password") && (
            <p className="hint">
              Use at least 12 characters. A memorable passphrase works well.
            </p>
          )}
          {error && <Notice error>{error}</Notice>}
          {message && <Notice>{message}</Notice>}
          <button disabled={busy}>
            {busy
              ? "Please wait…"
              : path === "login"
                ? "Sign in"
                : path === "register"
                  ? "Create account"
                  : path === "forgot-password"
                    ? "Send reset link"
                    : "Reset password"}
          </button>
        </form>
        <div className="auth-links">
          {path === "login" ? (
            <>
              <Link href="/forgot-password">Forgot password?</Link>
              <p>
                New here? <Link href="/register">Create an account</Link>
              </p>
            </>
          ) : (
            <Link href="/login">Back to sign in</Link>
          )}
        </div>
      </section>
    </div>
  );
}

export default function WalletApp({ path }: { path: string }) {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [balance, setBalance] = useState("0");
  const [loading, setLoading] = useState(true);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [ticket, setTicket] = useState<Ticket | null>(null);
  const [comments, setComments] = useState<Comment[]>([]);
  const [detail, setDetail] = useState<Transfer | null>(null);
  const [adminRows, setAdminRows] = useState<AdminRow[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(false);
  const [direction, setDirection] = useState("all");
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [draft, setDraft] = useState<{
    recipientId: string;
    amount: number;
    note: string;
    key: string;
  } | null>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const isPublic = publicRoutes.includes(path);
  const section = path.split("/")[0];
  const adminView = path.split("/")[1] || "users";
  const load = useCallback(async () => {
    if (isPublic) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setReady(false);
    setError("");
    try {
      const me = await api<{ user: User }>("/auth/me");
      setUser(me.user);
      if (!path || path === "transfer") {
        const { wallet } = await api<{ wallet: { balance: string } }>(
          "/wallet",
        );
        setBalance(wallet.balance);
      }
      if (!path || path === "transactions") {
        const result = await api<{ items: Transfer[]; hasMore: boolean }>(
          `/transactions?page=${page}&limit=${path ? 10 : 5}&direction=${direction}&search=${encodeURIComponent(search)}`,
        );
        setTransfers(result.items);
        setHasMore(result.hasMore);
      }
      if (section === "transactions" && path.includes("/"))
        setDetail(
          (
            await api<{ transaction: Transfer }>(
              `/transactions/${path.split("/")[1]}`,
            )
          ).transaction,
        );
      if (path === "support") {
        const result = await api<{ items: Ticket[]; hasMore: boolean }>(
          `/tickets?page=${page}`,
        );
        setTickets(result.items);
        setHasMore(result.hasMore);
      }
      if (section === "support" && path.includes("/")) {
        const result = await api<{ ticket: Ticket; comments: Comment[] }>(
          `/tickets/${path.split("/")[1]}`,
        );
        setTicket(result.ticket);
        setComments(result.comments);
      }
      if (section === "admin" && adminView === "detections") {
        const result = await api<{ items: Detection[] }>("/admin/detections");
        setDetections(result.items);
        setHasMore(false);
      } else if (section === "admin") {
        const result = await api<{ items: AdminRow[]; hasMore: boolean }>(
          `/admin/${adminView}?page=${page}`,
        );
        setAdminRows(result.items);
        setHasMore(result.hasMore);
      }
      setReady(true);
    } catch (error) {
      if (error instanceof RequestError && error.status === 401)
        router.replace("/login");
      else setError(text(error));
    } finally {
      setLoading(false);
    }
  }, [path, isPublic, page, direction, search, section, adminView, router]);
  useEffect(() => {
    void load();
  }, [load]);
  async function action(work: () => Promise<void>) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await work();
    } catch (error) {
      setError(text(error));
    } finally {
      setBusy(false);
    }
  }
  if (isPublic) return <AuthForm path={path} />;
  const titles: Record<string, string> = {
    "": "Your wallet",
    transfer: "Send money",
    transactions: "Activity",
    support: "How can we help?",
    settings: "Account settings",
    admin: "Administration",
  };
  const known = [
    "",
    "transfer",
    "transactions",
    "support",
    "settings",
    "admin",
  ].includes(section);
  function activity() {
    return transfers.length ? (
      <div className="activity-list">
        {transfers.map((t) => {
          const outgoing = t.sender_id === user?.id;
          return (
            <Link
              className="activity-row"
              key={t.id}
              href={`/transactions/${t.id}`}
            >
              <span className="activity-symbol" aria-hidden="true">
                {outgoing ? "−" : "+"}
              </span>
              <span className="activity-person">
                <strong>
                  {outgoing
                    ? `To ${t.recipient_name}`
                    : `From ${t.sender_name}`}
                </strong>
                <small>
                  {date(t.created_at)}
                  {t.note ? ` · ${t.note}` : ""}
                </small>
              </span>
              <strong className={outgoing ? "amount" : "amount incoming"}>
                {outgoing ? "−" : "+"}
                {money(t.amount)}
              </strong>
            </Link>
          );
        })}
      </div>
    ) : (
      <div className="empty">
        <h3>No activity yet</h3>
        <p>Your incoming and outgoing transfers will appear here.</p>
        <Link href="/transfer">Make a transfer</Link>
      </div>
    );
  }
  function pagination() {
    return (
      <div className="pagination">
        <button
          className="secondary"
          disabled={page === 1 || loading}
          onClick={() => setPage((p) => p - 1)}
        >
          Previous
        </button>
        <span>Page {page}</span>
        <button
          className="secondary"
          disabled={!hasMore || loading}
          onClick={() => setPage((p) => p + 1)}
        >
          Next
        </button>
      </div>
    );
  }
  return (
    <div className="app-layout">
      <aside className="sidebar">
        <Link className="brand" href="/">
          <span className="brand-square" aria-hidden="true">
            S
          </span>
          SecureWallet
        </Link>
        <nav aria-label="Main navigation">
          {[
            ["", "Overview"],
            ["transfer", "Send money"],
            ["transactions", "Activity"],
            ["support", "Support"],
            ["settings", "Settings"],
            ...(user?.role === "admin" ? [["admin", "Admin"]] : []),
          ].map(([route, label]) => (
            <Link
              key={route}
              href={`/${route}`}
              aria-current={section === route ? "page" : undefined}
            >
              {label}
            </Link>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <span className="demo">Demo — fake funds</span>
          <p>{user?.name ?? "SecureWallet"}</p>
          <button
            className="signout"
            disabled={busy}
            onClick={() =>
              void action(async () => {
                await api("/auth/logout", { method: "POST" });
                router.push("/login");
              })
            }
          >
            Sign out
          </button>
        </div>
      </aside>
      <main id="main">
        <header className="page-header">
          <div>
            <h1>{known ? titles[section] : "Page not found"}</h1>
            <p className="muted">
              {!path
                ? `Good to see you${user ? `, ${user.name.split(" ")[0]}` : ""}. Here’s where things stand.`
                : section === "admin"
                  ? "Review accounts, support requests, and wallet activity."
                  : section === "support"
                    ? "Ask a question. We’ll keep the conversation here."
                    : "SecureWallet · INR account"}
            </p>
          </div>
          <span className="header-demo">Demo — fake funds</span>
        </header>
        {error && (
          <Notice error>
            {error}{" "}
            <button className="text-button" onClick={() => void load()}>
              Reload page
            </button>
          </Notice>
        )}
        {message && <Notice>{message}</Notice>}
        {loading ? (
          <p className="loading" role="status">
            Loading your wallet…
          </p>
        ) : ready ? (
          <>
            {!known && <Link href="/">Return to your wallet</Link>}
            {!path && (
              <>
                <section className="balance-panel">
                  <div>
                    <h2>Available balance</h2>
                    <p className="balance">{money(balance)}</p>
                    <p>Indian rupees · INR</p>
                  </div>
                  <Link className="button light" href="/transfer">
                    Send money
                  </Link>
                </section>
                <section className="account-strip">
                  <span>Your account ID</span>
                  <code>{user?.id}</code>
                  <button
                    className="text-button"
                    onClick={() =>
                      void action(async () => {
                        await navigator.clipboard.writeText(user?.id ?? "");
                        setMessage("Account ID copied.");
                      })
                    }
                  >
                    Copy
                  </button>
                </section>
                <section>
                  <div className="section-heading">
                    <h2>Recent activity</h2>
                    <Link href="/transactions">View all activity</Link>
                  </div>
                  {activity()}
                </section>
                <section className="support-strip">
                  <div>
                    <h3>A question about your wallet?</h3>
                    <p>
                      Our support conversations keep everything in one place.
                    </p>
                  </div>
                  <Link href="/support">Get help</Link>
                </section>
              </>
            )}
            {path === "transfer" && (
              <section className="form-panel">
                <p className="available">
                  Available to send <strong>{money(balance)}</strong>
                </p>
                {draft ? (
                  <div>
                    <h2>Review your transfer</h2>
                    <dl className="details">
                      <dt>Recipient account</dt>
                      <dd>
                        <code>{draft.recipientId}</code>
                      </dd>
                      <dt>Amount</dt>
                      <dd className="review-amount">{money(draft.amount)}</dd>
                      <dt>Note</dt>
                      <dd>{draft.note || "No note"}</dd>
                    </dl>
                    <p className="muted">
                      Check the account ID and amount before confirming.
                    </p>
                    <div className="actions">
                      <button
                        disabled={busy}
                        onClick={() =>
                          void action(async () => {
                            const result = await api<{ transfer: Transfer }>(
                              "/transfers",
                              {
                                method: "POST",
                                headers: { "Idempotency-Key": draft.key },
                                body: JSON.stringify({
                                  recipientId: draft.recipientId,
                                  amount: draft.amount,
                                  note: draft.note,
                                }),
                              },
                            );
                            router.push(`/transactions/${result.transfer.id}`);
                          })
                        }
                      >
                        {busy ? "Sending…" : "Confirm transfer"}
                      </button>
                      <button
                        className="secondary"
                        disabled={busy}
                        onClick={() => setDraft(null)}
                      >
                        Edit transfer
                      </button>
                    </div>
                  </div>
                ) : (
                  <form
                    onSubmit={(event) => {
                      event.preventDefault();
                      setError("");
                      try {
                        const data = new FormData(event.currentTarget);
                        setDraft({
                          recipientId: String(data.get("recipientId")),
                          amount: parsePaise(String(data.get("amount"))),
                          note: String(data.get("note")),
                          key: crypto.randomUUID(),
                        });
                      } catch (error) {
                        setError(text(error));
                      }
                    }}
                  >
                    <Field
                      label="Recipient account ID"
                      name="recipientId"
                      placeholder="Paste their account ID"
                      required
                    />
                    <Field
                      label="Amount in rupees"
                      name="amount"
                      inputMode="decimal"
                      placeholder="0.00"
                      required
                    />
                    <Field
                      label="Note (optional)"
                      name="note"
                      maxLength={200}
                      placeholder="What’s it for?"
                    />
                    <button>Review transfer</button>
                    <p className="hint">Transfers use demo funds only.</p>
                  </form>
                )}
              </section>
            )}
            {path === "transactions" && (
              <section>
                <form
                  className="filters"
                  onSubmit={(e) => {
                    e.preventDefault();
                    setPage(1);
                    setSearch(searchInput);
                  }}
                >
                  <label>
                    Direction
                    <select
                      value={direction}
                      onChange={(e) => {
                        setPage(1);
                        setDirection(e.target.value);
                      }}
                    >
                      <option value="all">All activity</option>
                      <option value="incoming">Money received</option>
                      <option value="outgoing">Money sent</option>
                    </select>
                  </label>
                  <Field
                    label="Search activity"
                    value={searchInput}
                    onChange={(e) => setSearchInput(e.target.value)}
                    placeholder="Name or note"
                  />
                  <button className="secondary">Search</button>
                </form>
                {activity()}
                {pagination()}
              </section>
            )}
            {detail && (
              <section className="form-panel">
                <span className="status">Completed</span>
                <h2 className="receipt-amount">{money(detail.amount)}</h2>
                <dl className="details">
                  <dt>From account</dt>
                  <dd>
                    <code>{detail.sender_id}</code>
                  </dd>
                  <dt>To account</dt>
                  <dd>
                    <code>{detail.recipient_id}</code>
                  </dd>
                  <dt>Date</dt>
                  <dd>{date(detail.created_at)}</dd>
                  <dt>Note</dt>
                  <dd>{detail.note || "No note"}</dd>
                  <dt>Reference</dt>
                  <dd>
                    <code>{detail.id}</code>
                  </dd>
                </dl>
                <Link href="/transactions">Back to activity</Link>
              </section>
            )}
            {path === "support" && (
              <div className="support-grid">
                <section>
                  <h2>Your conversations</h2>
                  {tickets.length ? (
                    <div className="ticket-list">
                      {tickets.map((t) => (
                        <Link key={t.id} href={`/support/${t.id}`}>
                          <strong>{t.subject}</strong>
                          <span className="status">{t.status}</span>
                          <small>{date(t.created_at)}</small>
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <div className="empty">
                      <h3>No conversations yet</h3>
                      <p>Start a conversation using the form.</p>
                    </div>
                  )}
                  {pagination()}
                </section>
                <section className="form-panel">
                  <h2>Start a conversation</h2>
                  <form
                    onSubmit={(event) => {
                      event.preventDefault();
                      const values = Object.fromEntries(
                        new FormData(event.currentTarget),
                      );
                      void action(async () => {
                        const result = await api<{ ticket: Ticket }>(
                          "/tickets",
                          { method: "POST", body: JSON.stringify(values) },
                        );
                        router.push(`/support/${result.ticket.id}`);
                      });
                    }}
                  >
                    <Field
                      label="Subject"
                      name="subject"
                      maxLength={120}
                      required
                    />
                    <label className="field">
                      <span>How can we help?</span>
                      <textarea
                        name="body"
                        rows={5}
                        maxLength={5000}
                        required
                      />
                    </label>
                    <button disabled={busy}>
                      {busy ? "Sending…" : "Send message"}
                    </button>
                  </form>
                </section>
              </div>
            )}
            {ticket && (
              <section className="conversation">
                <Link
                  href={user?.role === "admin" ? "/admin/tickets" : "/support"}
                >
                  Back to conversations
                </Link>
                <div className="section-heading">
                  <h2>{ticket.subject}</h2>
                  <span className="status">{ticket.status}</span>
                </div>
                {comments.map((c) => (
                  <article className="comment" key={c.id}>
                    <header>
                      <strong>
                        {c.name}
                        {c.role === "admin" ? " · Support" : ""}
                      </strong>
                      <time>{date(c.created_at)}</time>
                    </header>
                    <p>{c.body}</p>
                  </article>
                ))}
                {ticket.status === "open" ? (
                  <form
                    ref={formRef}
                    onSubmit={(event) => {
                      event.preventDefault();
                      const body = new FormData(event.currentTarget).get(
                        "body",
                      );
                      void action(async () => {
                        await api(`/tickets/${ticket.id}/comments`, {
                          method: "POST",
                          body: JSON.stringify({ body }),
                        });
                        formRef.current?.reset();
                        await load();
                      });
                    }}
                  >
                    <label className="field">
                      <span>Your reply</span>
                      <textarea
                        name="body"
                        maxLength={5000}
                        rows={4}
                        required
                      />
                    </label>
                    <button disabled={busy}>
                      {busy ? "Sending…" : "Send reply"}
                    </button>
                  </form>
                ) : (
                  <p>This conversation is closed.</p>
                )}
                {user?.role === "admin" && (
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() =>
                      void action(async () => {
                        await api(`/admin/tickets/${ticket.id}`, {
                          method: "PATCH",
                          body: JSON.stringify({
                            status:
                              ticket.status === "open" ? "closed" : "open",
                          }),
                        });
                        await load();
                      })
                    }
                  >
                    {ticket.status === "open"
                      ? "Close conversation"
                      : "Reopen conversation"}
                  </button>
                )}
              </section>
            )}
            {path === "settings" && (
              <section className="form-panel">
                <h2>Change your password</h2>
                <p className="muted">
                  You’ll be signed out of all sessions after this change.
                </p>
                <form
                  onSubmit={(event) => {
                    event.preventDefault();
                    const values = Object.fromEntries(
                      new FormData(event.currentTarget),
                    );
                    void action(async () => {
                      await api("/auth/password", {
                        method: "POST",
                        body: JSON.stringify(values),
                      });
                      router.push("/login");
                    });
                  }}
                >
                  <Field
                    label="Current password"
                    name="currentPassword"
                    type="password"
                    autoComplete="current-password"
                    required
                  />
                  <Field
                    label="New password"
                    name="newPassword"
                    type="password"
                    autoComplete="new-password"
                    minLength={12}
                    maxLength={128}
                    required
                  />
                  <button disabled={busy}>
                    {busy ? "Saving…" : "Change password"}
                  </button>
                </form>
              </section>
            )}
            {section === "admin" && user?.role === "admin" && (
              <section>
                <nav className="tabs" aria-label="Administration">
                  {[
                    ["users", "Users"],
                    ["tickets", "Support"],
                    ["transactions", "Transfers"],
                    ["audit-events", "Security events"],
                    ["detections", "Detections"],
                  ].map(([route, label]) => (
                    <Link
                      aria-current={route === adminView ? "page" : undefined}
                      key={route}
                      href={`/admin/${route}`}
                    >
                      {label}
                    </Link>
                  ))}
                </nav>
                {adminView === "detections" ? (
                  detections.length ? (
                    <div className="table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>Alert</th>
                            <th>Subject</th>
                            <th>Observed</th>
                          </tr>
                        </thead>
                        <tbody>
                          {detections.map((d) => (
                            <tr key={d.id}>
                              <td>
                                <strong>
                                  {d.rule} · {d.title}
                                </strong>
                                <small>{d.response}</small>
                              </td>
                              <td>{d.subject}</td>
                              <td>
                                {d.count} in {d.window_minutes} min
                                <small>
                                  threshold {d.threshold} · last{" "}
                                  {date(d.last_seen)}
                                </small>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    !error && (
                      <p className="empty">
                        No detection rule is currently firing.
                      </p>
                    )
                  )
                ) : adminRows.length ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>
                            {adminView === "users"
                              ? "Account"
                              : adminView === "tickets"
                                ? "Subject"
                                : adminView === "transactions"
                                  ? "Transfer"
                                  : "Event"}
                          </th>
                          <th>
                            {adminView === "users"
                              ? "Role"
                              : adminView === "transactions"
                                ? "Amount"
                                : "Status / date"}
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {adminRows.map((row) => (
                          <tr key={row.id}>
                            <td>
                              {row.subject ? (
                                <Link href={`/support/${row.id}`}>
                                  {row.subject}
                                </Link>
                              ) : row.name ? (
                                <>
                                  <strong>{row.name}</strong>
                                  <small>{row.email}</small>
                                </>
                              ) : row.event ? (
                                row.event
                                  .replaceAll(".", " · ")
                                  .replaceAll("_", " ")
                              ) : (
                                <code>{row.id}</code>
                              )}
                            </td>
                            <td>
                              {row.role ??
                                (row.amount
                                  ? money(row.amount)
                                  : (row.status ?? date(row.created_at)))}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  !error && <p className="empty">No records to show.</p>
                )}
                {adminView === "detections" ? null : pagination()}
              </section>
            )}
          </>
        ) : null}
        <footer>
          SecureWallet <span>Thoughtfully simple. Always demo funds.</span>
        </footer>
      </main>
    </div>
  );
}
