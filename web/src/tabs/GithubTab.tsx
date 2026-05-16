"use client";
import { useMemo, useState } from "react";
import type { PkgByPackageItem, LangByLanguageItem, TopPackageItem, TopLanguageItem, CweLanguageStatsItem } from "@/types";
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
    topPackages: TopPackageItem[] | null;
    topLanguages: TopLanguageItem[] | null;
    topStatsLoading: boolean;
    ecosystems: string[];
    topEco: string;
    onEcoChange: (eco: string) => void;
    cweStats: CweLanguageStatsItem[] | null;
    cweStatsLoading: boolean;
    loadCweStats: () => void;
}

function formatBytes(b: number): string {
    if (b >= 1e9) return (b / 1e9).toFixed(1) + " GB";
    if (b >= 1e6) return (b / 1e6).toFixed(1) + " MB";
    if (b >= 1e3) return (b / 1e3).toFixed(1) + " KB";
    return b + " B";
}

export function GithubTab({
    depsStats, langsStats, statsLoading, loadGithubStats,
    pkgName, setPkgName, pkgEco, setPkgEco, pkgResults, pkgLoading, pkgError, searchByPackage,
    langName, setLangName, langResults, langLoading, langError, searchByLanguage,
    topPackages, topLanguages, topStatsLoading, ecosystems, topEco, onEcoChange,
    cweStats, cweStatsLoading, loadCweStats,
}: GithubTabProps) {
    const [cweLangFilter, setCweLangFilter] = useState("");

    const cweStatsSorted = useMemo(() => {
        if (!cweStats) return null;
        if (!cweLangFilter) return cweStats;
        return [...cweStats]
            .map((cwe) => {
                const totalBytes = cwe.languages.reduce((s, l) => s + l.total_bytes, 0);
                const pct = totalBytes > 0
                    ? (cwe.languages.find(l => l.language === cweLangFilter)?.total_bytes ?? 0) / totalBytes * 100
                    : 0;
                return { cwe, pct };
            })
            .sort((a, b) => b.pct - a.pct)
            .map((x) => x.cwe);
    }, [cweStats, cweLangFilter]);

    const cweAllLangs = useMemo(() => {
        if (!cweStats) return [];
        const langs = new Set<string>();
        for (const cwe of cweStats) {
            for (const l of cwe.languages) {
                langs.add(l.language);
            }
        }
        return [...langs].sort();
    }, [cweStats]);

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

            {/* Top dependencies */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 space-y-3">
                <div className="flex items-center gap-3">
                    <h3 className="text-sm font-semibold">Top 依赖项（按仓库数）</h3>
                    {ecosystems.length > 0 && (
                        <select
                            className="rounded border border-slate-200 px-2 py-1 text-xs outline-none focus:border-blue-400"
                            value={topEco}
                            onChange={(e) => onEcoChange(e.target.value)}
                        >
                            <option value="">全部 ecosystem</option>
                            {ecosystems.map((eco) => (
                                <option key={eco} value={eco}>{eco}</option>
                            ))}
                        </select>
                    )}
                    {topEco && (
                        <button
                            className="text-xs text-slate-400 hover:text-slate-600"
                            onClick={() => onEcoChange("")}
                        >
                            清除
                        </button>
                    )}
                </div>
                {topPackages === null && !topStatsLoading && (
                    <p className="text-xs text-slate-400">点击刷新统计加载</p>
                )}
                {topStatsLoading && <p className="text-xs text-slate-400">加载中…</p>}
                {topPackages !== null && (
                    topPackages.length === 0
                        ? <p className="text-sm text-slate-500">无数据</p>
                        : <div className="overflow-x-auto max-h-80 overflow-y-auto">
                            <table className="w-full text-xs">
                                <thead>
                                    <tr className="border-b border-slate-200 text-left text-slate-500 sticky top-0 bg-white">
                                        <th className="pb-2 pr-4 font-medium w-8">#</th>
                                        <th className="pb-2 pr-4 font-medium">包名</th>
                                        <th className="pb-2 pr-4 font-medium">ecosystem</th>
                                        <th className="pb-2 font-medium text-right">仓库数</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100">
                                    {topPackages.map((item, i) => (
                                        <tr key={item.package_name + (item.ecosystem ?? "")} className="text-slate-700 hover:bg-slate-50">
                                            <td className="py-1.5 pr-4 text-slate-400">{i + 1}</td>
                                            <td className="py-1.5 pr-4 font-medium">{item.package_name}</td>
                                            <td className="py-1.5 pr-4 text-slate-500">{item.ecosystem ?? "-"}</td>
                                            <td className="py-1.5 text-right font-mono">{item.repo_count}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                )}
            </div>

            {/* Top languages */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 space-y-3">
                <h3 className="text-sm font-semibold">语言分布（Top 50）</h3>
                {topLanguages === null && !topStatsLoading && (
                    <p className="text-xs text-slate-400">点击刷新统计加载</p>
                )}
                {topStatsLoading && <p className="text-xs text-slate-400">加载中…</p>}
                {topLanguages !== null && (
                    topLanguages.length === 0
                        ? <p className="text-sm text-slate-500">无数据</p>
                        : <div className="overflow-x-auto max-h-80 overflow-y-auto">
                            <table className="w-full text-xs">
                                <thead>
                                    <tr className="border-b border-slate-200 text-left text-slate-500 sticky top-0 bg-white">
                                        <th className="pb-2 pr-4 font-medium w-8">#</th>
                                        <th className="pb-2 pr-4 font-medium">语言</th>
                                        <th className="pb-2 pr-4 font-medium text-right">总字节</th>
                                        <th className="pb-2 pr-4 font-medium text-right">仓库数</th>
                                        <th className="pb-2 pr-4 font-medium text-right">CVE 数</th>
                                        <th className="pb-2 font-medium text-right">CWE 数</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100">
                                    {topLanguages.map((item, i) => (
                                        <tr key={item.language} className="text-slate-700 hover:bg-slate-50">
                                            <td className="py-1.5 pr-4 text-slate-400">{i + 1}</td>
                                            <td className="py-1.5 pr-4">
                                                <span className="flex items-center gap-1.5">
                                                    <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: LANG_COLORS[item.language] ?? "#8b949e" }} />
                                                    <span className="font-medium">{item.language}</span>
                                                </span>
                                            </td>
                                            <td className="py-1.5 pr-4 text-right font-mono text-slate-500">{formatBytes(item.total_bytes)}</td>
                                            <td className="py-1.5 pr-4 text-right font-mono">{item.repo_count}</td>
                                            <td className="py-1.5 pr-4 text-right font-mono">{item.cve_count}</td>
                                            <td className="py-1.5 text-right font-mono">{item.cwe_count}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                )}
            </div>

            {/* CWE-language distribution */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 space-y-3">
                <div className="flex items-center gap-3">
                    <h3 className="text-sm font-semibold">按 CWE 的语言分布</h3>
                    <button
                        className="rounded border border-slate-200 bg-white px-3 py-1 text-xs text-slate-600 hover:bg-slate-50 disabled:opacity-50"
                        disabled={cweStatsLoading}
                        onClick={loadCweStats}
                    >
                        {cweStatsLoading ? "加载中…" : cweStats === null ? "点击加载" : "刷新"}
                    </button>
                    {cweStats && cweAllLangs.length > 0 && (
                        <select
                            className="rounded border border-slate-200 px-2 py-1 text-xs outline-none focus:border-blue-400"
                            value={cweLangFilter}
                            onChange={(e) => setCweLangFilter(e.target.value)}
                        >
                            <option value="">默认排序</option>
                            {cweAllLangs.map((lang) => (
                                <option key={lang} value={lang}>按 {lang} 占比排序</option>
                            ))}
                        </select>
                    )}
                    {cweLangFilter && (
                        <button
                            className="text-xs text-slate-400 hover:text-slate-600"
                            onClick={() => setCweLangFilter("")}
                        >
                            清除
                        </button>
                    )}
                </div>
                {cweStats !== null && cweStats.length === 0 && !cweStatsLoading && (
                    <p className="text-sm text-slate-500">无数据</p>
                )}
                {cweStatsSorted !== null && (
                    cweStatsSorted.length === 0
                        ? <p className="text-sm text-slate-500">无数据</p>
                        : <div className="overflow-x-auto max-h-96 overflow-y-auto">
                            <table className="w-full text-xs">
                                <thead>
                                    <tr className="border-b border-slate-200 text-left text-slate-500 sticky top-0 bg-white">
                                        <th className="pb-2 pr-4 font-medium">CWE</th>
                                        <th className="pb-2 pr-4 font-medium">Top 语言</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100">
                                    {cweStatsSorted.map((cwe) => {
                                        const totalBytes = cwe.languages.reduce((s, l) => s + l.total_bytes, 0);
                                        return (
                                            <tr key={cwe.cwe_id} className="text-slate-700 hover:bg-slate-50 align-top">
                                                <td className="py-1.5 pr-4 font-mono font-medium whitespace-nowrap">{cwe.cwe_id}</td>
                                                <td className="py-1.5">
                                                    <div className="flex flex-wrap gap-x-2 gap-y-0.5">
                                                        {cwe.languages.map((l) => {
                                                            const pct = totalBytes > 0 ? (l.total_bytes / totalBytes * 100).toFixed(1) : "0.0";
                                                            const highlighted = cweLangFilter && l.language === cweLangFilter;
                                                            return (
                                                                <span key={l.language} className={`inline-flex items-center gap-1 ${highlighted ? "font-semibold text-blue-700" : "text-slate-600"}`}>
                                                                    <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: LANG_COLORS[l.language] ?? "#8b949e" }} />
                                                                    <span>{l.language}</span>
                                                                    <span className={highlighted ? "text-blue-500" : "text-slate-400"}>({pct}%)</span>
                                                                </span>
                                                            );
                                                        })}
                                                    </div>
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                )}
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
