"use client";
import type { GhsaRecord } from "@/types";

type GhsaStats = {
    total: number;
    reviewed: number;
    withdrawn: number;
    ecosystems: Record<string, number>;
};

interface GhsaTabProps {
    stats: GhsaStats | null;
    statsLoading: boolean;
    loadStats: () => void;
    pkgEco: string;
    setPkgEco: (v: string) => void;
    pkgName: string;
    setPkgName: (v: string) => void;
    pkgResults: GhsaRecord[] | null;
    pkgTotal: number;
    pkgLoading: boolean;
    pkgError: string;
    searchByPackage: () => void;
}

function GhsaCard({ entry }: { entry: GhsaRecord }) {
    return (
        <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-4 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
                <a
                    href={`https://github.com/advisories/${entry.ghsa_id}`}
                    target="_blank"
                    rel="noreferrer"
                    className="font-mono text-sm font-semibold text-blue-700 hover:underline"
                >
                    {entry.ghsa_id}
                </a>
                {entry.github_reviewed && (
                    <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-700">已审核</span>
                )}
                {entry.withdrawn && (
                    <span className="rounded-full bg-rose-100 px-2 py-0.5 text-xs font-medium text-rose-700">已撤销</span>
                )}
                {entry.severity_type && (
                    <span className="rounded-full bg-slate-200 px-2 py-0.5 text-xs text-slate-600">{entry.severity_type}</span>
                )}
                {entry.cvss_score !== null && (
                    <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-mono text-amber-700">CVSS {entry.cvss_score}</span>
                )}
            </div>

            {entry.summary && (
                <p className="text-sm text-slate-700">{entry.summary}</p>
            )}

            {entry.affected.length > 0 && (
                <div className="space-y-1">
                    <div className="text-xs font-medium text-slate-500">受影响的包</div>
                    <div className="flex flex-wrap gap-2">
                        {entry.affected.map((pkg, i) => (
                            <div key={i} className="rounded border border-slate-200 bg-white px-2 py-1 text-xs space-y-0.5">
                                <div className="font-medium text-slate-700">{pkg.ecosystem}/{pkg.package_name}</div>
                                {pkg.version_ranges.map((vr, j) => (
                                    <div key={j} className="font-mono text-slate-500">
                                        {vr.introduced && <span>introduced: {vr.introduced}</span>}
                                        {vr.introduced && (vr.fixed || vr.last_affected) && <span className="mx-1">→</span>}
                                        {vr.fixed && <span>fixed: {vr.fixed}</span>}
                                        {!vr.fixed && vr.last_affected && <span>last_affected: {vr.last_affected}</span>}
                                    </div>
                                ))}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {entry.cwe_ids.length > 0 && (
                <div className="flex flex-wrap gap-1">
                    {entry.cwe_ids.map((cwe) => (
                        <span key={cwe} className="rounded bg-slate-200 px-1.5 py-0.5 font-mono text-xs text-slate-600">{cwe}</span>
                    ))}
                </div>
            )}

            {entry.cve_ids.length > 0 && (
                <div className="flex flex-wrap gap-1">
                    {entry.cve_ids.map((cve) => (
                        <span key={cve} className="rounded bg-blue-100 px-1.5 py-0.5 font-mono text-xs text-blue-700">{cve}</span>
                    ))}
                </div>
            )}
        </div>
    );
}

export function GhsaTab({
    stats, statsLoading, loadStats,
    pkgEco, setPkgEco, pkgName, setPkgName,
    pkgResults, pkgTotal, pkgLoading, pkgError, searchByPackage,
}: GhsaTabProps) {
    const sortedEcosystems = stats
        ? Object.entries(stats.ecosystems).sort((a, b) => b[1] - a[1])
        : [];

    return (
        <section className="mt-4 space-y-4">
            <div className="flex items-center gap-3">
                <h2 className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-600">GHSA 安全公告</h2>
                <button
                    className="rounded border border-slate-200 bg-white px-3 py-1 text-xs text-slate-600 hover:bg-slate-50 disabled:opacity-50"
                    disabled={statsLoading}
                    onClick={loadStats}
                >
                    {statsLoading ? "加载中…" : stats === null ? "加载统计" : "刷新统计"}
                </button>
            </div>

            {/* Stats panel */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 space-y-3">
                <h3 className="text-sm font-semibold">概览</h3>
                {stats === null && !statsLoading && (
                    <p className="text-xs text-slate-400">点击"加载统计"查看数据</p>
                )}
                {statsLoading && <p className="text-xs text-slate-400">加载中…</p>}
                {stats !== null && (
                    <div className="space-y-3">
                        <div className="flex flex-wrap gap-4">
                            <div className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-2 text-center">
                                <div className="text-2xl font-bold text-slate-800">{stats.total.toLocaleString()}</div>
                                <div className="text-xs text-slate-500">总计</div>
                            </div>
                            <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-2 text-center">
                                <div className="text-2xl font-bold text-emerald-700">{stats.reviewed.toLocaleString()}</div>
                                <div className="text-xs text-emerald-600">已审核</div>
                            </div>
                            <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-2 text-center">
                                <div className="text-2xl font-bold text-rose-700">{stats.withdrawn.toLocaleString()}</div>
                                <div className="text-xs text-rose-600">已撤销</div>
                            </div>
                        </div>

                        {sortedEcosystems.length > 0 && (
                            <div>
                                <div className="mb-1.5 text-xs font-medium text-slate-500">Ecosystem 分布</div>
                                <div className="overflow-x-auto max-h-64 overflow-y-auto">
                                    <table className="w-full text-xs">
                                        <thead>
                                            <tr className="border-b border-slate-200 text-left text-slate-500 sticky top-0 bg-white">
                                                <th className="pb-1.5 pr-4 font-medium">Ecosystem</th>
                                                <th className="pb-1.5 font-medium text-right">数量</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {sortedEcosystems.map(([eco, count]) => (
                                                <tr key={eco} className="border-b border-slate-100 hover:bg-slate-50">
                                                    <td className="py-1 pr-4 font-mono text-slate-700">{eco}</td>
                                                    <td className="py-1 text-right font-mono">{count.toLocaleString()}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>

            {/* Package search panel */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 space-y-3">
                <h3 className="text-sm font-semibold">按包名查询</h3>
                <div className="flex flex-wrap gap-2">
                    <input
                        className="w-36 rounded border border-slate-200 px-3 py-2 text-sm outline-none focus:border-blue-400"
                        placeholder="ecosystem（可选）"
                        value={pkgEco}
                        onChange={(e) => setPkgEco(e.target.value)}
                        onKeyDown={(e) => { if (e.key === "Enter") searchByPackage(); }}
                    />
                    <input
                        className="min-w-0 flex-1 rounded border border-slate-200 px-3 py-2 text-sm outline-none focus:border-blue-400"
                        placeholder="包名，如 lodash"
                        value={pkgName}
                        onChange={(e) => setPkgName(e.target.value)}
                        onKeyDown={(e) => { if (e.key === "Enter") searchByPackage(); }}
                    />
                    <button
                        className="rounded bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50"
                        disabled={pkgLoading}
                        onClick={searchByPackage}
                    >
                        {pkgLoading ? "查询中…" : "查询"}
                    </button>
                </div>
                {pkgError && <p className="text-xs text-rose-600">{pkgError}</p>}
                {pkgResults !== null && (
                    pkgResults.length === 0
                        ? <p className="text-sm text-slate-500">无结果</p>
                        : (
                            <div className="space-y-2">
                                <div className="text-xs text-slate-400">共 {pkgTotal} 条结果</div>
                                {pkgResults.map((entry) => (
                                    <GhsaCard key={entry.ghsa_id} entry={entry} />
                                ))}
                            </div>
                        )
                )}
            </div>
        </section>
    );
}
