import Image from "next/image";
import Link from "next/link";

const controls = [
  {
    number: "01",
    title: "Sessions stay server-side.",
    body: "Opaque session tokens live in secure cookies. Logout and password changes revoke access on the server.",
  },
  {
    number: "02",
    title: "Transfers commit together.",
    body: "Row locks, database transactions, integer paise, and idempotency protect every balance movement.",
  },
  {
    number: "03",
    title: "Permissions follow the resource.",
    body: "Ownership and role checks run in the API for wallets, transfers, support tickets, and admin views.",
  },
];

export default function LandingPage() {
  return (
    <div className="landing-page">
      <a className="landing-skip" href="#landing-main">
        Skip to content
      </a>

      <header className="landing-header">
        <nav className="landing-nav" aria-label="Landing page navigation">
          <Link
            className="landing-brand"
            href="/"
            aria-label="SecureWallet home"
          >
            <span className="landing-brand-mark" aria-hidden="true">
              S
            </span>
            SecureWallet
          </Link>
          <div className="landing-nav-links">
            <a href="#product">Product</a>
            <a href="#security">Security</a>
            <a href="#lab">AppSec lab</a>
          </div>
          <Link className="landing-nav-cta" href="/login">
            Open demo
          </Link>
        </nav>
      </header>

      <main id="landing-main">
        <section className="landing-hero" aria-labelledby="landing-title">
          <div className="landing-shell landing-hero-grid">
            <div className="landing-hero-copy">
              <p className="landing-eyebrow">Digital wallet · AppSec lab</p>
              <h1 id="landing-title">A wallet that shows its work.</h1>
              <p className="landing-lead">
                Move fake money, inspect real controls, and trace each security
                decision from risk to remediation.
              </p>
              <div className="landing-actions">
                <Link className="landing-cta landing-cta-primary" href="/login">
                  Open demo
                </Link>
                <a
                  className="landing-cta landing-cta-secondary"
                  href="#security"
                >
                  View controls
                </a>
              </div>
            </div>

            <figure className="landing-hero-visual">
              <Image
                src="/wallet-hero.webp"
                alt="Forest-green wallet object in a softly lit studio"
                width={1536}
                height={1024}
                priority
                sizes="(max-width: 900px) 100vw, 52vw"
              />
              <figcaption>
                <span>Secure by design</span>
                <span>Demo · fake funds</span>
              </figcaption>
            </figure>
          </div>
        </section>

        <section className="landing-principles" aria-label="Core principles">
          <div className="landing-shell landing-principles-grid">
            <p>Real application flows</p>
            <p>Server-enforced access</p>
            <p>Explainable remediation</p>
          </div>
        </section>

        <section className="landing-section landing-product" id="product">
          <div className="landing-shell landing-product-grid">
            <div className="landing-product-frame">
              <Image
                src="/wallet-product.webp"
                alt="SecureWallet dashboard showing a demo INR balance"
                width={1440}
                height={960}
                sizes="(max-width: 900px) 100vw, 60vw"
              />
            </div>
            <div className="landing-product-copy">
              <h2>A wallet people can understand.</h2>
              <p>
                Check a balance, send INR demo funds, review activity, and keep
                support conversations together in one calm interface.
              </p>
              <dl className="landing-product-list">
                <div>
                  <dt>Money model</dt>
                  <dd>Integer paise with a balanced ledger</dd>
                </div>
                <div>
                  <dt>Account model</dt>
                  <dd>Normal users and controlled admin access</dd>
                </div>
                <div>
                  <dt>Content model</dt>
                  <dd>Plain-text support conversations</dd>
                </div>
              </dl>
            </div>
          </div>
        </section>

        <section className="landing-section landing-security" id="security">
          <div className="landing-shell">
            <div className="landing-section-heading">
              <h2>Controls you can point to.</h2>
              <p>
                Each layer answers a concrete failure mode and has a test that
                exercises the boundary.
              </p>
            </div>
            <div className="landing-control-grid">
              {controls.map((control, index) => (
                <article
                  className={`landing-control landing-control-${index + 1}`}
                  key={control.number}
                >
                  <span>{control.number}</span>
                  <div>
                    <h3>{control.title}</h3>
                    <p>{control.body}</p>
                  </div>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="landing-section landing-lab" id="lab">
          <div className="landing-shell landing-lab-grid">
            <div>
              <h2>Learn from both sides of the fix.</h2>
              <p>
                The local-only vulnerable lab demonstrates broken access
                control, injection, stored XSS, and transfer logic flaws beside
                their secured implementations.
              </p>
            </div>
            <div className="landing-lab-note">
              <p>Public boundary</p>
              <strong>The vulnerable lab never ships to Vercel.</strong>
              <span>
                Reports, evidence, source review, and automated checks remain in
                the project repository.
              </span>
            </div>
          </div>
        </section>

        <section className="landing-final">
          <div className="landing-shell landing-final-inner">
            <div>
              <h2>Step inside the wallet.</h2>
              <p>Use the seeded account to explore every secure user flow.</p>
            </div>
            <Link className="landing-cta landing-cta-primary" href="/login">
              Open demo
            </Link>
          </div>
        </section>
      </main>

      <footer className="landing-footer">
        <div className="landing-shell">
          <Link className="landing-brand" href="/">
            <span className="landing-brand-mark" aria-hidden="true">
              S
            </span>
            SecureWallet
          </Link>
          <p>Portfolio demonstration. No real money or payment rails.</p>
        </div>
      </footer>
    </div>
  );
}
