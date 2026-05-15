"use client";
import { STATUS_ORDER } from "@/lib/utils";

export function GithubStatsCard({
    title,
    stats,
    totalKey,
    totalLabel,
}: {
    title: string;
    stats: Record<string, number> | null;
    totalKey: string;
    totalLabel: string;
}) {
    if (!stats) {
        return (
            <div className="rounded-xl border border-slate-200 bg-white p-4">
                <h3 className="text-sm font-semibold">{title}</h3>
                <p className="mt-3 text-xs text-slate-400">暂无数据，点击"刷新统计"加载。</p>
            </div>
        );
    }

    const statusEntries = STATUS_ORDER
        .filter((s) => s in stats)
        .map((s) => [s, stats[s]] as [string, number]);
    const otherEntries = Object.entries(stats).filter(
        ([k]) => !STATUS_ORDER.includes(k) && k !== totalKey && k !== "pending_by_priority"
    );
    const total = statusEntries.reduce((acc, [, v]) => acc + v, 0);

    const statusColor: Record<string, string> = {
        fetched: "text-emerald-700 bg-emerald-50",
        not_modified: "text-sky-700 bg-sky-50",
        pending: "text-amber-700 bg-amber-50",
        error: "text-rose-700 bg-rose-50",
        skip_404: "text-slate-500 bg-slate-100",
        skip_403: "text-slate-500 bg-slate-100",
    };

    return (
        <div className="rounded-xl border border-slate-200 bg-white p-4 space-y-3">
            <div className="flex items-baseline justify-between">
                <h3 className="text-sm font-semibold">{title}</h3>
                <span className="text-xs text-slate-500">{total} 仓库</span>
            </div>

            <div className="flex flex-wrap gap-2">
                {statusEntries.map(([status, count]) => (
                    <span key={status} className={`rounded-full px-2.5 py-1 text-[11px] font-medium ${statusColor[status] ?? "text-slate-600 bg-slate-100"}`}>
                        {status}: {count}
                    </span>
                ))}
            </div>

            {stats[totalKey] !== undefined && (
                <p className="text-xs text-slate-500">{totalLabel}: {stats[totalKey].toLocaleString()}</p>
            )}

            {otherEntries.length > 0 && (
                <div className="text-xs text-slate-500 space-y-0.5">
                    {otherEntries.map(([k, v]) => (
                        <div key={k}>{k}: {String(v)}</div>
                    ))}
                </div>
            )}
        </div>
    );
}
