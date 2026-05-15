"use client";
import type { FilterDraft, PoCRuleMode, RawItem, TriMode } from "@/types";
import { API_BASE } from "@/lib/api";
import { normalizeTri, normalizeRule, riskTone, summarizePoc, scoreText, toneClass, unique } from "@/lib/utils";
import { PageControls } from "@/components/PageControls";
import { SummaryLine } from "@/components/SummaryLine";
import { LabeledLine } from "@/components/LabeledLine";
import { LinkLine } from "@/components/LinkLine";

interface SearchTabProps {
    filteredRows: RawItem[];
    stats: { critical: number; high: number; patch: number; poc: number };
    page: number;
    totalPages: number;
    pageSize: number;
    applied: FilterDraft;
    draft: FilterDraft;
    setDraft: React.Dispatch<React.SetStateAction<FilterDraft>>;
    loading: boolean;
    error: string;
    hasUnappliedChanges: boolean;
    resetDraftAndApply: () => void;
    applyDraft: () => void;
    runQuery: (page: number, pageSize: number) => void;
    openDetail: (item: RawItem) => void;
    query: { total: number } | null;
}

export function SearchTab({
    filteredRows, stats, page, totalPages, pageSize, applied, draft, setDraft,
    loading, error, hasUnappliedChanges, resetDraftAndApply, applyDraft,
    runQuery, openDetail, query,
}: SearchTabProps) {
    return (
        <div className="mt-4 grid gap-4 xl:grid-cols-[300px_minmax(0,1fr)]">
            <aside className="sticky top-4 self-start rounded-xl border border-slate-200 bg-white p-3 shadow-[0_8px_25px_rgba(15,23,42,0.06)]">
                <div className="flex items-center justify-between">
                    <div>
                        <h2 className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-600">Filters</h2>
                        <p className="mt-1 text-[11px] text-slate-500">大数据场景下仅在点击应用后筛选</p>
                    </div>
                    <button
                        className="rounded border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-slate-700"
                        onClick={() => setDraft((prev) => ({ ...prev, showAdvanced: !prev.showAdvanced }))}
                    >
                        {draft.showAdvanced ? "收起" : "高级"}
                    </button>
                </div>

                <div className="mt-3 rounded border border-slate-200 bg-slate-50 px-2 py-2 text-[11px] text-slate-600">
                    <div className="flex items-center justify-between gap-2">
                        <span className="truncate">{API_BASE}</span>
                        <span className={`rounded-full px-2 py-0.5 ${loading ? "bg-amber-100 text-amber-700" : "bg-emerald-100 text-emerald-700"}`}>
                            {loading ? "同步中" : "在线"}
                        </span>
                    </div>
                    <div className="mt-1 flex items-center justify-between text-slate-500">
                        <span>{query?.total ?? 0} total</span>
                        <span>{page}/{totalPages}</span>
                    </div>
                </div>

                <div className="mt-3 space-y-2">
                    <input
                        className="w-full rounded border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-400"
                        placeholder="cve:CVE-2024 cwe:79 sev:high patch:yes poc:no nginx"
                        value={draft.search}
                        onChange={(e) => setDraft((prev) => ({ ...prev, search: e.target.value }))}
                    />

                    <div className="grid grid-cols-2 gap-2">
                        <select className="rounded border border-slate-200 bg-white px-2 py-2 text-sm" value={draft.patchOnly} onChange={(e) => setDraft((prev) => ({ ...prev, patchOnly: normalizeTri(e.target.value) }))}>
                            <option value="all">Patch 全部</option>
                            <option value="yes">有 Patch</option>
                            <option value="no">无 Patch</option>
                        </select>
                        <select className="rounded border border-slate-200 bg-white px-2 py-2 text-sm" value={draft.pocOnly} onChange={(e) => setDraft((prev) => ({ ...prev, pocOnly: normalizeTri(e.target.value) }))}>
                            <option value="all">PoC 全部</option>
                            <option value="yes">有 PoC</option>
                            <option value="no">无 PoC</option>
                        </select>
                    </div>

                    <div className="grid grid-cols-2 gap-2">
                        <select className="rounded border border-slate-200 bg-white px-2 py-2 text-sm" value={draft.refOnly} onChange={(e) => setDraft((prev) => ({ ...prev, refOnly: normalizeTri(e.target.value) }))}>
                            <option value="all">引用 全部</option>
                            <option value="yes">有引用</option>
                            <option value="no">无引用</option>
                        </select>
                        <select className="rounded border border-slate-200 bg-white px-2 py-2 text-sm" value={draft.detailOnly} onChange={(e) => setDraft((prev) => ({ ...prev, detailOnly: normalizeTri(e.target.value) }))}>
                            <option value="all">详情链接 全部</option>
                            <option value="yes">有详情链接</option>
                            <option value="no">无详情链接</option>
                        </select>
                    </div>

                    <select className="w-full rounded border border-slate-200 bg-white px-2 py-2 text-sm" value={draft.pocRuleMode} onChange={(e) => setDraft((prev) => ({ ...prev, pocRuleMode: normalizeRule(e.target.value) }))}>
                        <option value="balanced">PoC 规则: balanced</option>
                        <option value="strict">PoC 规则: strict</option>
                        <option value="loose">PoC 规则: loose</option>
                    </select>

                    {draft.showAdvanced ? (
                        <div className="grid gap-2 rounded border border-slate-200 bg-slate-50 p-2">
                            <input className="rounded border border-slate-200 bg-white px-2 py-2 text-sm" type="date" value={draft.from} onChange={(e) => setDraft((prev) => ({ ...prev, from: e.target.value }))} />
                            <input className="rounded border border-slate-200 bg-white px-2 py-2 text-sm" type="date" value={draft.to} onChange={(e) => setDraft((prev) => ({ ...prev, to: e.target.value }))} />
                        </div>
                    ) : null}
                </div>

                <div className="mt-4 grid grid-cols-2 gap-2">
                    <button className="rounded border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700" onClick={resetDraftAndApply}>清空</button>
                    <button className="rounded bg-blue-600 px-3 py-2 text-xs font-medium text-white hover:bg-blue-500" onClick={applyDraft}>{loading ? "Loading..." : "应用筛选"}</button>
                </div>

                {hasUnappliedChanges ? <p className="mt-2 text-[11px] text-amber-700">筛选已修改，点击"应用筛选"后生效。</p> : null}
                {error ? <p className="mt-2 text-xs text-rose-600">{error}</p> : null}
            </aside>

            <section className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2">
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600">
                        <span className="rounded-full bg-slate-100 px-2.5 py-1">{filteredRows.length} visible</span>
                        <span className="rounded-full bg-slate-100 px-2.5 py-1">高危 {stats.high}</span>
                        <span className="rounded-full bg-slate-100 px-2.5 py-1">严重 {stats.critical}</span>
                        <span className="rounded-full bg-slate-100 px-2.5 py-1">PoC {stats.poc}</span>
                    </div>
                    <PageControls page={page} totalPages={totalPages} pageSize={pageSize} onPage={(p) => runQuery(p, pageSize)} onPageSize={(size) => runQuery(1, size)} />
                </div>

                <div className="divide-y divide-slate-200 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-[0_12px_28px_rgba(15,23,42,0.07)]">
                    {filteredRows.map((item) => {
                        const poc = summarizePoc(item, applied.pocRuleMode);
                        const severityTone = riskTone(item.severity);
                        const cweText = [item.cwe_id || "-", item.cwe_description || "-"].filter(Boolean).join(" | ");
                        const cvssText = `score=${scoreText(item.cvss_score)} | vector=${item.cvss_vector || "-"}`;
                        return (
                            <article key={item.cve_id} className="px-4 py-4">
                                <div className="flex flex-wrap items-start gap-2">
                                    <h3 className="text-sm font-semibold text-slate-950">
                                        {item.title || "无标题"}
                                        <span className="ml-2 font-mono text-xs text-slate-500">{item.cve_id}</span>
                                    </h3>
                                    <span className={`rounded-full px-2 py-0.5 text-[11px] ring-1 ${toneClass(severityTone)}`}>{item.severity || "unknown"}</span>
                                    <span className={`rounded-full px-2 py-0.5 text-[11px] ring-1 ${toneClass(poc.tone)}`}>{poc.label}</span>
                                    <div className="ml-auto flex items-center gap-2">
                                        <button className="rounded border border-slate-200 bg-slate-50 px-2 py-1 text-[11px]" onClick={() => openDetail(item)}>展开</button>
                                        {item.detail_url ? <a className="rounded border border-slate-200 bg-slate-50 px-2 py-1 text-[11px]" href={item.detail_url} target="_blank" rel="noreferrer">跳转</a> : null}
                                    </div>
                                </div>

                                <div className="mt-2 space-y-2 text-sm text-slate-700">
                                    <SummaryLine text={item.description || "暂无描述"} />
                                    <div className="grid gap-2 md:grid-cols-2">
                                        <LabeledLine label="CWE" text={cweText} />
                                        <LabeledLine label="CVSS" text={cvssText} mono />
                                    </div>
                                    <div className="grid gap-2 md:grid-cols-2">
                                        <LinkLine title="引用链接（原始）" urls={unique(item.references || [])} />
                                        <LinkLine title="补丁链接（提取）" urls={unique(item.patch_urls || [])} />
                                    </div>
                                </div>
                            </article>
                        );
                    })}

                    {filteredRows.length === 0 ? (
                        <div className="px-4 py-12 text-center text-sm text-slate-500">没有匹配结果，调整筛选后再试。</div>
                    ) : null}
                </div>

                <div className="flex justify-end">
                    <PageControls page={page} totalPages={totalPages} pageSize={pageSize} onPage={(p) => runQuery(p, pageSize)} onPageSize={(size) => runQuery(1, size)} />
                </div>
            </section>
        </div>
    );
}
