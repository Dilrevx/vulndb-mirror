"use client";
import { useMemo, useState } from "react";
import type { PkgByPackageItem, LangByLanguageItem, TopPackageItem, TopLanguageItem, CweLanguageStatsItem } from "@/types";
import { LANG_COLORS } from "@/lib/utils";
import { GithubStatsCard } from "@/components/GithubStatsCard";
import { useColumnResize } from "@/hooks/useColumnResize";
import { useTableVirtualizer, useDynamicTableVirtualizer } from "@/hooks/useTableVirtualizer";

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

    const topPkgResize = useColumnResize({ pkg: 200, eco: 100 });
    const topLangResize = useColumnResize({ lang: 160 });
    const cweResize = useColumnResize({ cwe: 320 });
    const pkgResize = useColumnResize({ repo: 220, eco: 100, pkg: 140 });
    const langResize = useColumnResize({ repo: 220, lang: 120 });

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

    const topPkgVirt = useTableVirtualizer(topPackages?.length ?? 0);
    const topLangVirt = useTableVirtualizer(topLanguages?.length ?? 0);
    const cweVirt = useDynamicTableVirtualizer(cweStatsSorted?.length ?? 0);
    const pkgVirt = useTableVirtualizer(pkgResults?.length ?? 0);
    const langVirt = useTableVirtualizer(langResults?.length ?? 0);

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
                        : <div ref={topPkgVirt.scrollRef} className="overflow-x-auto max-h-80 overflow-y-auto">
                            <table ref={topPkgResize.tableRef} className="w-full text-xs">
                                <thead>
                                    <tr className="flex border-b border-slate-200 text-left text-slate-500 sticky top-0 bg-white z-10">
                                        <th className="pb-2 pr-4 font-medium flex-none w-8">#</th>
                                        <th style={topPkgResize.thStyle("pkg")} className="pb-2 pr-4 font-medium flex-none relative">
                                            <span className="block truncate pr-2">包名</span>
                                            <div className="absolute right-0 top-0 bottom-0 w-3 cursor-col-resize group" onMouseDown={topPkgResize.onResizeStart("pkg")}>
                                                <div className="absolute right-1 top-0 bottom-0 w-px bg-slate-200 group-hover:bg-blue-400 transition-colors" />
                                            </div>
                                        </th>
                                        <th style={topPkgResize.thStyle("eco")} className="pb-2 pr-4 font-medium flex-none relative">
                                            <span className="block truncate pr-2">ecosystem</span>
                                            <div className="absolute right-0 top-0 bottom-0 w-3 cursor-col-resize group" onMouseDown={topPkgResize.onResizeStart("eco")}>
                                                <div className="absolute right-1 top-0 bottom-0 w-px bg-slate-200 group-hover:bg-blue-400 transition-colors" />
                                            </div>
                                        </th>
                                        <th className="pb-2 font-medium text-right flex-1">仓库数</th>
                                    </tr>
                                </thead>
                                <tbody style={{ height: topPkgVirt.virtualizer.getTotalSize() }} className="relative block">
                                    {topPkgVirt.virtualizer.getVirtualItems().map((vRow) => {
                                        const item = topPackages[vRow.index];
                                        return (
                                            <tr key={vRow.key} data-index={vRow.index} className="flex absolute w-full text-slate-700 hover:bg-slate-50 border-b border-slate-100" style={{ transform: `translateY(${vRow.start}px)` }}>
                                                <td className="py-1.5 pr-4 text-slate-400 flex-none w-8">{vRow.index + 1}</td>
                                                <td className="py-1.5 pr-4 font-medium flex-none overflow-hidden" style={topPkgResize.thStyle("pkg")}><span className="block truncate">{item.package_name}</span></td>
                                                <td className="py-1.5 pr-4 text-slate-500 flex-none overflow-hidden" style={topPkgResize.thStyle("eco")}><span className="block truncate">{item.ecosystem ?? "-"}</span></td>
                                                <td className="py-1.5 text-right font-mono flex-1">{item.repo_count}</td>
                                            </tr>
                                        );
                                    })}
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
                        : <div ref={topLangVirt.scrollRef} className="overflow-x-auto max-h-80 overflow-y-auto">
                            <table ref={topLangResize.tableRef} className="w-full text-xs">
                                <thead>
                                    <tr className="flex border-b border-slate-200 text-left text-slate-500 sticky top-0 bg-white z-10">
                                        <th className="pb-2 pr-4 font-medium flex-none w-8">#</th>
                                        <th style={topLangResize.thStyle("lang")} className="pb-2 pr-4 font-medium flex-none relative">
                                            <span className="block truncate pr-2">语言</span>
                                            <div className="absolute right-0 top-0 bottom-0 w-3 cursor-col-resize group" onMouseDown={topLangResize.onResizeStart("lang")}>
                                                <div className="absolute right-1 top-0 bottom-0 w-px bg-slate-200 group-hover:bg-blue-400 transition-colors" />
                                            </div>
                                        </th>
                                        <th className="pb-2 pr-4 font-medium flex-1">总字节</th>
                                        <th className="pb-2 pr-4 font-medium flex-none w-14">仓库数</th>
                                        <th className="pb-2 pr-4 font-medium flex-none w-14">CVE 数</th>
                                        <th className="pb-2 font-medium flex-none w-14">CWE 数</th>
                                    </tr>
                                </thead>
                                <tbody style={{ height: topLangVirt.virtualizer.getTotalSize() }} className="relative block">
                                    {topLangVirt.virtualizer.getVirtualItems().map((vRow) => {
                                        const item = topLanguages[vRow.index];
                                        return (
                                            <tr key={vRow.key} data-index={vRow.index} className="flex absolute w-full text-slate-700 hover:bg-slate-50 border-b border-slate-100" style={{ transform: `translateY(${vRow.start}px)` }}>
                                                <td className="py-1.5 pr-4 text-slate-400 flex-none w-8">{vRow.index + 1}</td>
                                                <td className="py-1.5 pr-4 flex-none overflow-hidden" style={topLangResize.thStyle("lang")}>
                                                    <span className="flex items-center gap-1.5 min-w-0">
                                                        <span className="inline-block h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: LANG_COLORS[item.language] ?? "#8b949e" }} />
                                                        <span className="font-medium truncate">{item.language}</span>
                                                    </span>
                                                </td>
                                                <td className="py-1.5 pr-4 font-mono text-slate-500 flex-1">{formatBytes(item.total_bytes)}</td>
                                                <td className="py-1.5 pr-4 font-mono flex-none w-14">{item.repo_count}</td>
                                                <td className="py-1.5 pr-4 font-mono flex-none w-14">{item.cve_count}</td>
                                                <td className="py-1.5 font-mono flex-none w-14">{item.cwe_count}</td>
                                            </tr>
                                        );
                                    })}
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
                        : <div ref={cweVirt.scrollRef} className="overflow-x-auto max-h-96 overflow-y-auto">
                            <table ref={cweResize.tableRef} className="w-full text-xs">
                                <thead>
                                    <tr className="flex border-b border-slate-200 text-left text-slate-500 sticky top-0 bg-white z-10">
                                        <th style={cweResize.thStyle("cwe")} className="pb-2 pr-4 font-medium flex-none relative">
                                            <span className="block truncate pr-2">CWE</span>
                                            <div className="absolute right-0 top-0 bottom-0 w-3 cursor-col-resize group" onMouseDown={cweResize.onResizeStart("cwe")}>
                                                <div className="absolute right-1 top-0 bottom-0 w-px bg-slate-200 group-hover:bg-blue-400 transition-colors" />
                                            </div>
                                        </th>
                                        <th className="pb-2 pr-4 font-medium flex-1">Top 语言</th>
                                    </tr>
                                </thead>
                                <tbody style={{ height: cweVirt.virtualizer.getTotalSize() }} className="relative block">
                                    {cweVirt.virtualizer.getVirtualItems().map((vRow) => {
                                        const cwe = cweStatsSorted[vRow.index];
                                        const totalBytes = cwe.languages.reduce((s, l) => s + l.total_bytes, 0);
                                        return (
                                            <tr key={vRow.key} data-index={vRow.index} ref={cweVirt.virtualizer.measureElement} className="flex absolute w-full text-slate-700 hover:bg-slate-50 border-b border-slate-100 items-start" style={{ transform: `translateY(${vRow.start}px)` }}>
                                                <td className="py-1.5 pr-4 flex-none overflow-hidden" style={cweResize.thStyle("cwe")}>
                                                    <span className="flex items-baseline gap-1.5 min-w-0">
                                                        <span className="font-mono font-medium shrink-0">{cwe.cwe_id}</span>
                                                        {cwe.cwe_description && (
                                                            <span className="text-slate-500 truncate" title={cwe.cwe_description}>
                                                                {cwe.cwe_description}
                                                            </span>
                                                        )}
                                                    </span>
                                                </td>
                                                <td className="py-1.5 flex-1">
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
                        : <div ref={pkgVirt.scrollRef} className="overflow-x-auto max-h-96 overflow-y-auto">
                            <table ref={pkgResize.tableRef} className="w-full text-xs">
                                <thead>
                                    <tr className="flex border-b border-slate-200 text-left text-slate-500 sticky top-0 bg-white z-10">
                                        <th style={pkgResize.thStyle("repo")} className="pb-2 pr-4 font-medium flex-none relative">
                                            <span className="block truncate pr-2">仓库</span>
                                            <div className="absolute right-0 top-0 bottom-0 w-3 cursor-col-resize group" onMouseDown={pkgResize.onResizeStart("repo")}>
                                                <div className="absolute right-1 top-0 bottom-0 w-px bg-slate-200 group-hover:bg-blue-400 transition-colors" />
                                            </div>
                                        </th>
                                        <th style={pkgResize.thStyle("eco")} className="pb-2 pr-4 font-medium flex-none relative">
                                            <span className="block truncate pr-2">ecosystem</span>
                                            <div className="absolute right-0 top-0 bottom-0 w-3 cursor-col-resize group" onMouseDown={pkgResize.onResizeStart("eco")}>
                                                <div className="absolute right-1 top-0 bottom-0 w-px bg-slate-200 group-hover:bg-blue-400 transition-colors" />
                                            </div>
                                        </th>
                                        <th style={pkgResize.thStyle("pkg")} className="pb-2 pr-4 font-medium flex-none relative">
                                            <span className="block truncate pr-2">包名</span>
                                            <div className="absolute right-0 top-0 bottom-0 w-3 cursor-col-resize group" onMouseDown={pkgResize.onResizeStart("pkg")}>
                                                <div className="absolute right-1 top-0 bottom-0 w-px bg-slate-200 group-hover:bg-blue-400 transition-colors" />
                                            </div>
                                        </th>
                                        <th className="pb-2 pr-4 font-medium flex-1">版本</th>
                                        <th className="pb-2 pr-4 font-medium flex-none w-16">关系</th>
                                        <th className="pb-2 font-medium flex-none w-14">CVE 数</th>
                                    </tr>
                                </thead>
                                <tbody style={{ height: pkgVirt.virtualizer.getTotalSize() }} className="relative block">
                                    {pkgVirt.virtualizer.getVirtualItems().map((vRow) => {
                                        const item = pkgResults[vRow.index];
                                        return (
                                            <tr key={vRow.key} data-index={vRow.index} className="flex absolute w-full text-slate-700 border-b border-slate-100 hover:bg-slate-50" style={{ transform: `translateY(${vRow.start}px)` }}>
                                                <td className="py-1.5 pr-4 font-mono flex-none overflow-hidden" style={pkgResize.thStyle("repo")}>
                                                    <a href={`https://github.com/${item.owner}/${item.repo}`} target="_blank" rel="noreferrer" className="block truncate text-blue-700 hover:underline">
                                                        {item.owner}/{item.repo}
                                                    </a>
                                                </td>
                                                <td className="py-1.5 pr-4 text-slate-500 flex-none overflow-hidden" style={pkgResize.thStyle("eco")}><span className="block truncate">{item.ecosystem ?? "-"}</span></td>
                                                <td className="py-1.5 pr-4 flex-none overflow-hidden" style={pkgResize.thStyle("pkg")}><span className="block truncate">{item.package_name}</span></td>
                                                <td className="py-1.5 pr-4 text-slate-500 flex-1 truncate">{item.version_info ?? "-"}</td>
                                                <td className="py-1.5 pr-4 text-slate-500 flex-none w-16">{item.relationship ?? "-"}</td>
                                                <td className="py-1.5 flex-none w-14">{item.source_cves.length}</td>
                                            </tr>
                                        );
                                    })}
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
                        : <div ref={langVirt.scrollRef} className="overflow-x-auto max-h-96 overflow-y-auto">
                            <table ref={langResize.tableRef} className="w-full text-xs">
                                <thead>
                                    <tr className="flex border-b border-slate-200 text-left text-slate-500 sticky top-0 bg-white z-10">
                                        <th style={langResize.thStyle("repo")} className="pb-2 pr-4 font-medium flex-none relative">
                                            <span className="block truncate pr-2">仓库</span>
                                            <div className="absolute right-0 top-0 bottom-0 w-3 cursor-col-resize group" onMouseDown={langResize.onResizeStart("repo")}>
                                                <div className="absolute right-1 top-0 bottom-0 w-px bg-slate-200 group-hover:bg-blue-400 transition-colors" />
                                            </div>
                                        </th>
                                        <th style={langResize.thStyle("lang")} className="pb-2 pr-4 font-medium flex-none relative">
                                            <span className="block truncate pr-2">语言</span>
                                            <div className="absolute right-0 top-0 bottom-0 w-3 cursor-col-resize group" onMouseDown={langResize.onResizeStart("lang")}>
                                                <div className="absolute right-1 top-0 bottom-0 w-px bg-slate-200 group-hover:bg-blue-400 transition-colors" />
                                            </div>
                                        </th>
                                        <th className="pb-2 pr-4 font-medium flex-1">字节数</th>
                                        <th className="pb-2 pr-4 font-medium flex-none w-14">优先级</th>
                                        <th className="pb-2 font-medium flex-none w-14">CVE 数</th>
                                    </tr>
                                </thead>
                                <tbody style={{ height: langVirt.virtualizer.getTotalSize() }} className="relative block">
                                    {langVirt.virtualizer.getVirtualItems().map((vRow) => {
                                        const item = langResults[vRow.index];
                                        return (
                                            <tr key={vRow.key} data-index={vRow.index} className="flex absolute w-full text-slate-700 border-b border-slate-100 hover:bg-slate-50" style={{ transform: `translateY(${vRow.start}px)` }}>
                                                <td className="py-1.5 pr-4 font-mono flex-none overflow-hidden" style={langResize.thStyle("repo")}>
                                                    <a href={`https://github.com/${item.owner}/${item.repo}`} target="_blank" rel="noreferrer" className="block truncate text-blue-700 hover:underline">
                                                        {item.owner}/{item.repo}
                                                    </a>
                                                </td>
                                                <td className="py-1.5 pr-4 flex-none overflow-hidden" style={langResize.thStyle("lang")}>
                                                    <span className="flex items-center gap-1 min-w-0">
                                                        <span className="inline-block h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: LANG_COLORS[item.language] ?? "#8b949e" }} />
                                                        <span className="truncate">{item.language}</span>
                                                    </span>
                                                </td>
                                                <td className="py-1.5 pr-4 text-slate-500 flex-1">{(item.bytes / 1024).toFixed(1)} KB</td>
                                                <td className="py-1.5 pr-4 text-slate-500 flex-none w-14">{item.priority}</td>
                                                <td className="py-1.5 flex-none w-14">{item.source_cves.length}</td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                )}
            </div>
        </section>
    );
}
