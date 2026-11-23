const REDACTED = "[REDACTED]";

const SENSITIVE_KEY = /(?:access[_-]?token|refresh[_-]?token|\btoken\b|partner[_-]?key|api[_-]?key|client[_-]?secret|secret|password|passwd|authorization|cookie|database[_-]?url|connection[_-]?string|\bsign(?:ature)?\b)/i;
const SENSITIVE_PAIR = /((?:access[_-]?token|refresh[_-]?token|token|partner[_-]?key|api[_-]?key|client[_-]?secret|secret|password|passwd|authorization|cookie|database[_-]?url|connection[_-]?string|sign(?:ature)?)\s*["']?\s*[:=]\s*["']?)(?!\[REDACTED\])([^,"'&}\]\r\n]+)/gi;

function redactUrlCredentials(text: string): string {
    return text
        .replace(/([a-z][a-z\d+.-]*:\/\/)([^\s/@:]+)(?::[^\s/@]*)?@/gi, `$1${REDACTED}@`)
        .replace(/([?&](?:access[_-]?token|refresh[_-]?token|token|partner[_-]?key|api[_-]?key|client[_-]?secret|secret|password|passwd|authorization|cookie|sign(?:ature)?)=)[^&#\s]*/gi, `$1${REDACTED}`);
}

/** Redige credenciais antes que erros, respostas remotas ou objetos sejam exibidos. */
export function sanitizeSensitiveData(value: unknown, seen = new WeakSet<object>()): unknown {
    if (typeof value === "string") {
        return redactUrlCredentials(value).replace(SENSITIVE_PAIR, `$1${REDACTED}`);
    }
    if (value === null || typeof value !== "object") return value;
    if (seen.has(value)) return "[CIRCULAR]";
    seen.add(value);

    if (Array.isArray(value)) return value.map((item) => sanitizeSensitiveData(item, seen));

    if (value instanceof Error) {
        return {
            name: value.name,
            message: sanitizeErrorMessage(value.message),
        };
    }

    const sanitized: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
        sanitized[key] = SENSITIVE_KEY.test(key) ? REDACTED : sanitizeSensitiveData(item, seen);
    }
    return sanitized;
}

/** Converte um erro desconhecido em texto seguro para logs e mensagens públicas. */
export function sanitizeErrorMessage(error: unknown): string {
    const message = error instanceof Error ? error.message : typeof error === "string" ? error : String(error);
    return sanitizeSensitiveData(message) as string;
}
