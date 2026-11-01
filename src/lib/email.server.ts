// Email sending (server-only). Do not import from the browser.
//
// nodemailer over SMTP, called directly from the app. This is a known gap
// against the README's stated Cloudflare Workers production target — Workers
// cannot open raw TCP/SMTP sockets, and nodemailer needs a real one. It's the
// right call for how this app actually runs today (a persistent Node process,
// per the local dev setup), and the swap if that deploy ever happens is
// contained to this one file: everything else calls sendEmail() and never
// touches nodemailer or SMTP directly.

import nodemailer, { type Transporter } from "nodemailer";

export type SendEmailArgs = {
  to: string;
  subject: string;
  html: string;
  text: string;
};

function readConfig() {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.SMTP_FROM;

  const missing = [
    ...(!host ? ["SMTP_HOST"] : []),
    ...(!user ? ["SMTP_USER"] : []),
    ...(!pass ? ["SMTP_PASS"] : []),
    ...(!from ? ["SMTP_FROM"] : []),
  ];
  if (missing.length) {
    throw new Error(
      `Cannot send email: missing ${missing.join(", ")}. Set them in your environment.`,
    );
  }

  const port = Number(process.env.SMTP_PORT ?? 587);
  // Port 465 is implicit TLS; everything else (587, 25, Mailpit's 1025) starts
  // in plaintext and upgrades via STARTTLS. SMTP_SECURE lets a local test
  // server without any TLS at all (Mailpit) be told not to attempt it.
  const secure =
    process.env.SMTP_SECURE != null ? process.env.SMTP_SECURE === "true" : port === 465;

  return { host: host!, port, secure, user: user!, pass: pass!, from: from! };
}

let cachedTransporter: Transporter | undefined;
let cachedFrom: string | undefined;

function getTransporter(): { transporter: Transporter; from: string } {
  const config = readConfig();
  // Rebuild if SMTP_FROM (or anything else) changed since the last call —
  // relevant for tests, irrelevant in a real process where env is static.
  if (!cachedTransporter || cachedFrom !== config.from) {
    cachedTransporter = nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: config.secure,
      auth: { user: config.user, pass: config.pass },
    });
    cachedFrom = config.from;
  }
  return { transporter: cachedTransporter, from: cachedFrom };
}

export async function sendEmail(args: SendEmailArgs): Promise<void> {
  const { transporter, from } = getTransporter();
  await transporter.sendMail({
    from,
    to: args.to,
    subject: args.subject,
    html: args.html,
    text: args.text,
  });
}

/**
 * Opens a connection and authenticates, then disconnects — without sending
 * anything. Use this to check SMTP configuration in isolation: a digest email
 * only fires after a full weekly sweep completes, which is a slow and noisy
 * way to discover a typo'd password.
 *
 * Resolves on success; rejects with the provider's own error otherwise.
 */
export async function verifyEmailTransport(): Promise<void> {
  const { transporter } = getTransporter();
  await transporter.verify();
}
