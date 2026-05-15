"use client";
import type { PkgByPackageItem, LangByLanguageItem } from "@/types";
import { LANG_COLORS } from "@/lib/utils";
import { GithubStatsCard } from "@/components/GithubStatsCard";

interface GithubTabProps {
    depsStats: Record<string, number> | null;
    langsStats: Record<string, number> | null;
    statsLoading: boolean;
    loadGithubStats: () => void;
    pkgName: string;
    setPkgName: (v: string) => void;
    pkgEco: string;
    setPkgEco: (v: string) => void;
    pkgResults: PkgByPackageItem[] | null;
    pkgLoading: boolean;
    pkgError: string;
    searchByPackage: () => void;
    langName: string;
    setLangName: (v: string) => void;
    langResults: LangByLanguageItem[] | null;
    langLoading: boolean;
    langError: string;
    searchByLanguage: () => void;
}

export function GithubTab({
    depsStats, langsStats, statsLoading, loadGithubStats,
    pkgName, setPkgName, pkgEco, setPkgEco, pkgResults, pkgLoading, pkgError, searchByPackage,
    langName, setLangName, langResults, langLoading, langError, searchByLanguage,
}: GithubTabProps) {
    return (
        <section className="mt-4 space-y-4">
            <div className="flex items-center gap-3">
                <h2 className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-600">GitHub 缓存</h2>
                <button
                    className="rounded border border-slate-200 bg-white px-3 py-1 text-xs text-slate-600 hover:bg-slate-50 disabled:opacity-50"
                    disabled={statsLoading}
                    onClick={loadGithubStats}
                >
                    {statsLoading ? "加载中…" : "刷新统计"}
                </button>
            </div>

            <div className="grid gap-4 xl:grid-cols-2">
                <GithubStatsCard title="依赖图 (SBOM)" stats={depsStats} totalKey="total_packages" totalLabel="包总数" />
                <GithubStatsCard title="语言组成" stats={langsStats} totalKey="total_language_rows" totalLabel="语言行数" />
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-4 space-y-3">
                <h3 className="text-sm font-semibold">按包名反查仓库</h3>
                <div className="flex flex-wrap gap-2">
                    <input
                        className="min-w-0 flex-1 rounded border border-slate-200 px-3 py-2 text-sm outline-none focus:border-blue-400"
                        placeholder="包名，如 lodash"
                        value={pkgName}
                        onChange={(e) => setPkgName(e.target.value)}
                        onKeyDown={(e) => { if (e.key === "Enter") searchByPackage(); }}
                    />
                    <input
                        className="w-36 rounded border border-slate-200 px-3 py-2 text-sm outline-none focus:border-blue-400"
                        placeholder="ecosystem（可选）"
                        value={pkgEco}
                        onChange={(e) => setPkgEco(e.target.value)}
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
                        : <div className="overflow-x-auto">
                            <table className="w-full text-xs">
                                <thead>
                                    <tr className="border-b border-slate-200 text-left text-slate-500">
                                        <th className="pb-2 pr-4 font-medium">仓库</th>
                                        <th className="pb-2 pr-4 font-medium">ecosystem</th>
                                        <th className="pb-2 pr-4 font-medium">包名</th>
                                        <th className="pb-2 pr-4 font-medium">版本</th>
                                        <th className="pb-2 pr-4 font-medium">关系</th>
                                        <th className="pb-2 font-medium">CVE 数</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100">
                                    {pkgResults.map((item, i) => (
                                        <tr key={i} className="text-slate-700">
                                            <td className="py-1.5 pr-4 font-mono">
                                                <a href={`https://github.com/${item.owner}/${item.repo}`} target="_blank" rel="noreferrer" className="text-blue-700 hover:underline">
                                                    {item.owner}/{item.repo}
                                                </a>
                                            </td>
                                            <td className="py-1.5 pr-4 text-slate-500">{item.ecosystem ?? "-"}</td>
                                            <td className="py-1.5 pr-4">{item.package_name}</td>
                                            <td className="py-1.5 pr-4 text-slate-500">{item.version_info ?? "-"}</td>
                                            <td className="py-1.5 pr-4 text-slate-500">{item.relationship ?? "-"}</td>
                                            <td className="py-1.5">{item.source_cves.length}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                )}
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-4 space-y-3">
                <h3 className="text-sm font-semibold">按语言反查仓库</h3>
                <div className="flex flex-wrap gap-2">
                    <input
                        className="min-w-0 flex-1 rounded border border-slate-200 px-3 py-2 text-sm outline-none focus:border-blue-400"
                        placeholder="语言名，如 Python"
                        value={langName}
                        onChange={(e) => setLangName(e.target.value)}
                        onKeyDown={(e) => { if (e.key === "Enter") searchByLanguage(); }}
                    />
                    <button
                        className="rounded bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50"
                        disabled={langLoading}
                        onClick={searchByLanguage}
                    >
                        {langLoading ? "查询中…" : "查询"}
                    </button>
                </div>
                {langError && <p className="text-xs text-rose-600">{langError}</p>}
                {langResults !== null && (
                    langResults.length === 0
                        ? <p className="text-sm text-slate-500">无结果</p>
                        : <div className="overflow-x-auto">
                            <table className="w-full text-xs">
                                <thead>
                                    <tr className="border-b border-slate-200 text-left text-slate-500">
                                        <th className="pb-2 pr-4 font-medium">仓库</th>
                                        <th className="pb-2 pr-4 font-medium">语言</th>
                                        <th className="pb-2 pr-4 font-medium">字节数</th>
                                        <th className="pb-2 pr-4 font-medium">优先级</th>
                                        <th className="pb-2 font-medium">CVE 数</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100">
                                    {langResults.map((item, i) => (
                                        <tr key={i} className="text-slate-700">
                                            <td className="py-1.5 pr-4 font-mono">
                                                <a href={`https://github.com/${item.owner}/${item.repo}`} target="_blank" rel="noreferrer" className="text-blue-700 hover:underline">
                                                    {item.owner}/{item.repo}
                                                </a>
                                            </td>
                                            <td className="py-1.5 pr-4">
                                                <span className="flex items-center gap-1">
                                                    <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: LANG_COLORS[item.language] ?? "#8b949e" }} />
                                                    {item.language}
                                                </span>
                                            </td>
                                            <td className="py-1.5 pr-4 text-slate-500">{(item.bytes / 1024).toFixed(1)} KB</td>
                                            <td className="py-1.5 pr-4 text-slate-500">{item.priority}</td>
                                            <td className="py-1.5">{item.source_cves.length}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                )}
            </div>
        </section>
    );
}
