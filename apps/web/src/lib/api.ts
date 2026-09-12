let csrf = "";
export class RequestError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}
export async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const method = options.method ?? "GET";
  if (method !== "GET" && !csrf) {
    const response = await fetch("/api/v1/auth/csrf", { cache: "no-store" });
    if (!response.ok)
      throw new RequestError(
        "Cannot connect to the wallet. Try again.",
        response.status,
      );
    csrf = (await response.json()).csrfToken;
  }
  const response = await fetch(`/api/v1${path}`, {
    ...options,
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      ...(method !== "GET" ? { "X-CSRF-Token": csrf } : {}),
      ...options.headers,
    },
  });
  const data = await response
    .json()
    .catch(() => ({
      error: { message: "Cannot connect to the wallet. Try again." },
    }));
  if (!response.ok) {
    if (response.status === 403) csrf = "";
    throw new RequestError(
      data.error?.message ?? "Request failed.",
      response.status,
    );
  }
  if (data.csrfToken) csrf = data.csrfToken;
  return data as T;
}
export const money = (paise: string | number) =>
  new Intl.NumberFormat("en-IN", { style: "currency", currency: "INR" }).format(
    Number(paise) / 100,
  );
export function parsePaise(value: string): number {
  if (!/^\d+(\.\d{1,2})?$/.test(value))
    throw new Error("Enter an amount with up to two decimal places.");
  const [whole, fraction = ""] = value.split(".");
  const amount = BigInt(whole) * 100n + BigInt(fraction.padEnd(2, "0"));
  if (amount <= 0n || amount > 100000000n)
    throw new Error("Enter an amount between ₹0.01 and ₹10,00,000.");
  return Number(amount);
}
