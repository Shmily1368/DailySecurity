/** 通用格式化工具 */

export function formatDate(iso: string): string {
    try {
        const d = new Date(iso);
        if (isNaN(d.getTime())) return iso;
        return d.toISOString().slice(0, 10);
    } catch {
        return iso;
    }
}

export function formatPercent(v: number | undefined, digits = 0): string {
    if (v === undefined || v === null || Number.isNaN(v)) return '-';
    return `${(v * 100).toFixed(digits)}%`;
}

export function formatScore(v: number | undefined, digits = 2): string {
    if (v === undefined || v === null || Number.isNaN(v)) return '-';
    return v.toFixed(digits);
}

export function severityColor(s?: string): string {
    switch (s) {
        case 'critical':
            return '#b91c1c';
        case 'high':
            return '#dc2626';
        case 'medium':
            return '#d97706';
        case 'low':
            return '#2563eb';
        default:
            return '#6b7280';
    }
}
