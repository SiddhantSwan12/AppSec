import { z } from "zod";

/**
 * Shared text validation for anything that reaches a PostgreSQL `text` column.
 *
 * PostgreSQL cannot store code point 0 in a text value at all, so a NUL byte in
 * a request body is not a storage question but an unhandled driver error: it
 * surfaced as a 500 rather than a 400 (SW-11). The remaining C0 control
 * characters are rejected with it — they carry no meaning in a name, a subject
 * or a support message, and they make stored values behave unpredictably
 * wherever they are later displayed or logged.
 *
 * Tab (9), newline (10) and carriage return (13) are deliberately allowed: a
 * multi-line support message is legitimate input.
 *
 * Written as an explicit code-point scan rather than a regular expression so
 * the boundary is readable and cannot be mangled by source-level escaping.
 */
const allowedControlCodes = new Set([9, 10, 13]);

export const hasControlCharacters = (value: string): boolean => {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (allowedControlCodes.has(code)) continue;
    if (code < 32 || code === 127) return true;
  }
  return false;
};

const rejectControlCharacters = <T extends z.ZodType<string>>(schema: T) =>
  schema.refine((value) => !hasControlCharacters(value), {
    message: "Remove control characters from this field.",
  });

/** Required free text, trimmed, 1..max characters. */
export const safeText = (max: number) =>
  rejectControlCharacters(z.string().trim().min(1).max(max));

/** Optional free text that may be empty, trimmed, up to max characters. */
export const safeOptionalText = (max: number) =>
  rejectControlCharacters(z.string().trim().max(max));
