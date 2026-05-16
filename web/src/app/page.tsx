"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import type {
    ChannelId, CheckpointsResp, FilterDraft, GapsResp,
    GithubDepsData, GithubLangsData, LangByLanguageItem,
    PkgByPackageItem, QueryResp, RawItem, RepoGithubData, TabMode,
    TopPackageItem, TopLanguageItem, CweLanguageStatsItem,
} from "@/types";
import { apiGet, apiPost } from "@/lib/api";
import {
    DEFAULT_FILTERS, normalizeRule, normalizeSearchInput, normalizeTri,
    parseGithubRepos, parseSmartSearch, riskTone, scoreText, summarizePoc,
} from "@/lib/utils";
import { TabButton } from "@/components/TabButton";
import { LabeledLine } from "@/components/LabeledLine";
import { CollapsibleText } from "@/components/CollapsibleText";
import { GitHubRepoCard } from "@/components/GitHubRepoCard";
import { SearchTab } from "@/tabs/SearchTab";
import { DebugTab } from "@/tabs/DebugTab";
import { GithubTab } from "@/tabs/GithubTab";

export default function Home() {
    const [activeTab, setActiveTab] = useState<TabMode>("search");
    const [channel, setChannel] = useState<ChannelId>("cvelistv5");
    const [channelList, setChannelList] = useState<ChannelId[]>(["cvelistv5"]);
    const [query, setQuery] = useState<QueryResp | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    const [draft, setDraft] = useState<FilterDraft>(DEFAULT_FILTERS);
    const [applied, setApplied] = useState<FilterDraft>(DEFAULT_FILTERS);

    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(20);

    const [selected, setSelected] = useState<RawItem | null>(null);
    const [detailJson, setDetailJson] = useState("{}");
    const [repoData, setRepoData] = useState<Record<string, RepoGithubData>>({});

    const [cveId, setCveId] = useState("");
    const [maxPage, setMaxPage] = useState(500);
    const [gaps, setGaps] = useState<GapsResp | null>(null);
    const [checkpoints, setCheckpoints] = useState<CheckpointsResp | null>(null);
    const [retryPages, setRetryPages] = useState("");
    const [retryResult, setRetryResult] = useState("{}");
    const querySeqRef = useRef(0);
    const queryAbortRef = useRef<AbortController | null>(null);

    const [depsStats, setDepsStats] = useState<Record<string, number> | null>(null);
    const [langsStats, setLangsStats] = useState<Record<string, number> | null>(null);
    const [statsLoading, setStatsLoading] = useState(false);
    const [pkgName, setPkgName] = useState("");
    const [pkgEco, setPkgEco] = useState("");
    const [pkgResults, setPkgResults] = useState<PkgByPackageItem[] | null>(null);
    const [pkgLoading, setPkgLoading] = useState(false);
    const [pkgError, setPkgError] = useState("");
    const [langName, setLangName] = useState("");
    const [langResults, setLangResults] = useState<LangByLanguageItem[] | null>(null);
    const [langLoading, setLangLoading] = useState(false);
    const [langError, setLangError] = useState("");
    const [topPackages, setTopPackages] = useState<TopPackageItem[] | null>(null);
    const [topLanguages, setTopLanguages] = useState<TopLanguageItem[] | null>(null);
    const [topStatsLoading, setTopStatsLoading] = useState(false);
    const [topEco, setTopEco] = useState("");
    const [ecosystems, setEcosystems] = useState<string[]>([]);
    const [cweStats, setCweStats] = useState<CweLanguageStatsItem[] | null>(null);
    const [cweStatsLoading, setCweStatsLoading] = useState(false);

    const searchTokens = useMemo(() => parseSmartSearch(applied.search), [applied.search]);

    const filteredRows = useMemo(() => {
        const items = query?.items || [];
        return items.filter((item) => {
            const pool = [
                item.cve_id, item.title, item.description, item.cwe_id,
                item.cwe_description, item.severity, item.cvss_vector,
                ...(item.references || []), ...(item.patch_urls || []),
            ].filter(Boolean).join(" ").toLowerCase();

            if (searchTokens.text.length && !searchTokens.text.every((t) => pool.includes(t))) return false;
            if (searchTokens.cve && !item.cve_id.toLowerCase().includes(searchTokens.cve)) return false;
            if (searchTokens.cwe && !(item.cwe_id || "").toLowerCase().includes(searchTokens.cwe)) return false;
            if (searchTokens.severity && !(item.severity || "").toLowerCase().includes(searchTokens.severity)) return false;

            if (applied.patchOnly === "yes" && !(item.patch_urls || []).length) return false;
            if (applied.patchOnly === "no" && (item.patch_urls || []).length > 0) return false;
            if (applied.refOnly === "yes" && !(item.references || []).length) return false;
            if (applied.refOnly === "no" && (item.references || []).length > 0) return false;
            if (applied.detailOnly === "yes" && !item.detail_url) return false;
            if (applied.detailOnly === "no" && !!item.detail_url) return false;

            if (searchTokens.patch === "yes" && !(item.patch_urls || []).length) return false;
            if (searchTokens.patch === "no" && (item.patch_urls || []).length > 0) return false;

            const poc = summarizePoc(item, applied.pocRuleMode).label;
            if (applied.pocOnly === "yes" && poc === "未见 PoC 线索") return false;
            if (applied.pocOnly === "no" && poc !== "未见 PoC 线索") return false;
            if (searchTokens.poc === "yes" && poc === "未见 PoC 线索") return false;
            if (searchTokens.poc === "no" && poc !== "未见 PoC 线索") return false;

            return true;
        });
    }, [query, searchTokens, applied]);

    const stats = useMemo(() => {
        const critical = filteredRows.filter((x) => riskTone(x.severity) === "critical").length;
        const high = filteredRows.filter((x) => riskTone(x.severity) === "high").length;
        const patch = filteredRows.filter((x) => (x.patch_urls || []).length > 0).length;
        const poc = filteredRows.filter((x) => summarizePoc(x, applied.pocRuleMode).label !== "未见 PoC 线索").length;
        return { critical, high, patch, poc };
    }, [filteredRows, applied.pocRuleMode]);

    const totalPages = Math.max(1, Math.ceil((query?.total ?? 0) / pageSize));
    const hasUnappliedChanges = JSON.stringify(draft) !== JSON.stringify(applied);

    async function runQuery(targetPage = page, targetPageSize = pageSize, filters = applied, ch = channel): Promise<void> {
        const requestSeq = ++querySeqRef.current;
        queryAbortRef.current?.abort();
        const controller = new AbortController();
        queryAbortRef.current = controller;
        setQuery(null);
        setLoading(true);
        setError("");
        try {
            const params = new URLSearchParams({ page: String(targetPage), page_size: String(targetPageSize), channel: ch });
            const normalizedSearch = normalizeSearchInput(filters.search);
            if (normalizedSearch) params.set("q", normalizedSearch);
            if (filters.patchOnly === "yes") params.set("has_patch", "true");
            else if (filters.patchOnly === "no") params.set("has_patch", "false");
            if (filters.showAdvanced && filters.from) params.set("modified_from", filters.from);
            if (filters.showAdvanced && filters.to) params.set("modified_to", filters.to);
            const data = await apiGet<QueryResp>(`/raw?${params.toString()}`, { signal: controller.signal });
            if (requestSeq !== querySeqRef.current) return;
            setQuery(data);
            setPage(data.page);
            setPageSize(data.page_size);
        } catch (e) {
            if ((e as DOMException | Error | undefined)?.name === "AbortError") return;
            if (requestSeq !== querySeqRef.current) return;
            setError(String(e));
        } finally {
            if (requestSeq === querySeqRef.current) setLoading(false);
        }
    }

    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        const initPage = Number(params.get("page") || "1");
        const initPageSize = Number(params.get("page_size") || "20");
        const initChannel = params.get("channel") || "cvelistv5";
        const tabValue = params.get("tab");
        const initTab: TabMode = tabValue === "debug" || tabValue === "ops" ? "debug" : "search";
        const initFilters: FilterDraft = {
            search: params.get("q") || "",
            patchOnly: normalizeTri(params.get("patch")),
            pocOnly: normalizeTri(params.get("poc")),
            refOnly: normalizeTri(params.get("ref")),
            detailOnly: normalizeTri(params.get("detail")),
            pocRuleMode: normalizeRule(params.get("poc_rule")),
            showAdvanced: params.get("advanced") === "1",
            from: params.get("modified_from") || "",
            to: params.get("modified_to") || "",
        };

        setActiveTab(initTab);
        setChannel(initChannel);
        setDraft(initFilters);
        setApplied(initFilters);

        apiGet<{ channels: string[] }>("/channels").then((data) => {
            setChannelList(data.channels);
        }).catch(() => {});

        let mounted = true;
        void (async () => {
            const requestSeq = ++querySeqRef.current;
            queryAbortRef.current?.abort();
            const controller = new AbortController();
            queryAbortRef.current = controller;
            setLoading(true);
            setError("");
            try {
                const safePage = Math.max(1, initPage || 1);
                const safeSize = [10, 20, 50, 100].includes(initPageSize) ? initPageSize : 20;
                const queryParams = new URLSearchParams({ page: String(safePage), page_size: String(safeSize), channel: initChannel });
                const normalizedSearch = normalizeSearchInput(initFilters.search);
                if (normalizedSearch) queryParams.set("q", normalizedSearch);
                if (initFilters.patchOnly === "yes") queryParams.set("has_patch", "true");
                else if (initFilters.patchOnly === "no") queryParams.set("has_patch", "false");
                if (initFilters.showAdvanced && initFilters.from) queryParams.set("modified_from", initFilters.from);
                if (initFilters.showAdvanced && initFilters.to) queryParams.set("modified_to", initFilters.to);
                const data = await apiGet<QueryResp>(`/raw?${queryParams.toString()}`, { signal: controller.signal });
                if (!mounted || requestSeq !== querySeqRef.current) return;
                setQuery(data);
                setPage(data.page);
                setPageSize(data.page_size);
            } catch (e) {
                if ((e as DOMException | Error | undefined)?.name === "AbortError") return;
                if (!mounted || requestSeq !== querySeqRef.current) return;
                setError(String(e));
            } finally {
                if (mounted && requestSeq === querySeqRef.current) setLoading(false);
            }
        })();

        return () => { mounted = false; };
    }, []);

    useEffect(() => {
        const params = new URLSearchParams();
        params.set("page", String(page));
        params.set("page_size", String(pageSize));
        if (channel !== "aliyun") params.set("channel", channel);
        if (applied.showAdvanced) params.set("advanced", "1");
        if (applied.showAdvanced && applied.from) params.set("modified_from", applied.from);
        if (applied.showAdvanced && applied.to) params.set("modified_to", applied.to);
        if (applied.search) params.set("q", applied.search);
        if (applied.patchOnly !== "all") params.set("patch", applied.patchOnly);
        if (applied.pocOnly !== "all") params.set("poc", applied.pocOnly);
        if (applied.refOnly !== "all") params.set("ref", applied.refOnly);
        if (applied.detailOnly !== "all") params.set("detail", applied.detailOnly);
        if (applied.pocRuleMode !== "balanced") params.set("poc_rule", applied.pocRuleMode);
        if (activeTab !== "search") params.set("tab", activeTab);
        window.history.replaceState(null, "", `${window.location.pathname}?${params.toString()}`);
    }, [page, pageSize, applied, activeTab, channel]);

    function switchChannel(ch: ChannelId): void {
        setChannel(ch);
        if (ch !== "aliyun" && activeTab === "debug") setActiveTab("search");
        setPage(1);
        setSelected(null);
        setGaps(null);
        setCheckpoints(null);
        void runQuery(1, pageSize, applied, ch);
    }

    function resetDraftAndApply(): void {
        setPage(1);
        setDraft(DEFAULT_FILTERS);
        setApplied(DEFAULT_FILTERS);
        void runQuery(1, pageSize, DEFAULT_FILTERS);
    }

    function applyDraft(): void {
        setPage(1);
        setApplied(draft);
        void runQuery(1, pageSize, draft);
    }

    async function openDetail(item: RawItem): Promise<void> {
        setSelected(item);
        setRepoData({});
        try {
            const data = await apiGet<RawItem>(`/raw/${encodeURIComponent(item.cve_id)}?channel=${channel}`);
            setDetailJson(JSON.stringify(data, null, 2));
            const allUrls = [...(data.patch_urls || []), ...(data.references || [])];
            const repos = parseGithubRepos(allUrls);
            if (repos.length) {
                const initial: Record<string, RepoGithubData> = {};
                for (const { owner, repo } of repos) initial[`${owner}/${repo}`] = { langs: null, deps: null, loading: true };
                setRepoData(initial);
                for (const { owner, repo } of repos) {
                    const key = `${owner}/${repo}`;
                    void Promise.all([
                        apiGet<GithubLangsData>(`/github-languages/${owner}/${repo}`).catch(() => null),
                        apiGet<GithubDepsData>(`/github-deps/${owner}/${repo}`).catch(() => null),
                    ]).then(([langs, deps]) => {
                        setRepoData((prev) => ({ ...prev, [key]: { langs, deps, loading: false } }));
                    });
                }
            }
        } catch {
            setDetailJson(JSON.stringify(item, null, 2));
        }
    }

    async function debugLoadByCve(): Promise<void> {
        if (!cveId.trim()) return;
        try {
            const data = await apiGet<RawItem>(`/raw/${encodeURIComponent(cveId.trim())}?channel=${channel}`);
            await openDetail(data);
        } catch (e) {
            setRetryResult(String(e));
        }
    }

    async function debugLoadGaps(): Promise<void> {
        try {
            setGaps(await apiGet<GapsResp>(`/ops/aliyun/gaps?max_page=${maxPage}&include_failed=true`));
        } catch (e) {
            setGaps(null);
            setRetryResult(String(e));
        }
    }

    async function debugLoadCheckpoints(): Promise<void> {
        try {
            setCheckpoints(await apiGet<CheckpointsResp>(`/ops/aliyun/checkpoints`));
        } catch (e) {
            setCheckpoints(null);
            setRetryResult(String(e));
        }
    }

    async function debugRetryPages(): Promise<void> {
        const parsed = retryPages.split(/[\s,]+/).map((x) => Number(x)).filter((x) => Number.isInteger(x) && x > 0);
        if (!parsed.length) { setRetryResult("Please enter page numbers, e.g. 50 51 52"); return; }
        try {
            const data = await apiPost("/ops/aliyun/retry", { pages: parsed });
            setRetryResult(JSON.stringify(data, null, 2));
        } catch (e) {
            setRetryResult(String(e));
        }
    }

    async function loadGithubStats(): Promise<void> {
        setStatsLoading(true);
        setTopStatsLoading(true);
        // Fire-and-forget: CWE stats load asynchronously without blocking main panels
        void loadCweStats();
        try {
            const [d, l, tp, tl, eco] = await Promise.all([
                apiGet<Record<string, number>>("/github-deps/stats").catch(() => null),
                apiGet<Record<string, number>>("/github-languages/stats").catch(() => null),
                apiGet<{ items: TopPackageItem[] }>("/github-deps/top-packages?limit=50").catch(() => null),
                apiGet<{ items: TopLanguageItem[] }>("/github-languages/top-languages?limit=50").catch(() => null),
                apiGet<{ items: string[] }>("/github-deps/ecosystems").catch(() => null),
            ]);
            setDepsStats(d);
            setLangsStats(l);
            setTopPackages(tp?.items ?? null);
            setTopLanguages(tl?.items ?? null);
            setEcosystems(eco?.items ?? []);
        } finally {
            setStatsLoading(false);
            setTopStatsLoading(false);
        }
    }

    async function loadCweStats(): Promise<void> {
        setCweStatsLoading(true);
        try {
            const cwe = await apiGet<{ items: CweLanguageStatsItem[] }>("/github-languages/cwe-stats?limit=100").catch(() => null);
            setCweStats(cwe?.items ?? null);
        } finally {
            setCweStatsLoading(false);
        }
    }

    async function loadTopPackages(eco?: string): Promise<void> {
        setTopStatsLoading(true);
        try {
            const params = new URLSearchParams({ limit: "50" });
            if (eco) params.set("ecosystem", eco);
            const tp = await apiGet<{ items: TopPackageItem[] }>(`/github-deps/top-packages?${params}`).catch(() => null);
            setTopPackages(tp?.items ?? null);
        } finally {
            setTopStatsLoading(false);
        }
    }

    async function searchByPackage(): Promise<void> {
        if (!pkgName.trim()) return;
        setPkgLoading(true);
        setPkgError("");
        setPkgResults(null);
        try {
            const params = new URLSearchParams({ name: pkgName.trim() });
            if (pkgEco.trim()) params.set("ecosystem", pkgEco.trim());
            const data = await apiGet<{ items: PkgByPackageItem[] }>(`/github-deps/by-package?${params}`);
            setPkgResults(data.items);
        } catch (e) {
            setPkgError(String(e));
        } finally {
            setPkgLoading(false);
        }
    }

    async function searchByLanguage(): Promise<void> {
        if (!langName.trim()) return;
        setLangLoading(true);
        setLangError("");
        setLangResults(null);
        try {
            const data = await apiGet<{ items: LangByLanguageItem[] }>(`/github-languages/by-language?name=${encodeURIComponent(langName.trim())}`);
            setLangResults(data.items);
        } catch (e) {
            setLangError(String(e));
        } finally {
            setLangLoading(false);
        }
    }

    return (
        <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(59,130,246,0.16),_transparent_34%),linear-gradient(180deg,#f8fbff_0%,#eef2ff_100%)] text-slate-900">
            <main className="mx-auto max-w-[1700px] px-4 py-5 lg:px-6">
                <div className="flex items-center gap-2">
                    <TabButton label="漏洞检索" active={activeTab === "search"} onClick={() => setActiveTab("search")} />
                    {channel === "aliyun" ? (
                        <TabButton label="Aliyun 调试" active={activeTab === "debug"} onClick={() => setActiveTab("debug")} />
                    ) : null}
                    <TabButton label="GitHub 缓存" active={activeTab === "github"} onClick={() => { setActiveTab("github"); void loadGithubStats(); }} />
                    <div className="ml-auto">
                        <select
                            className="rounded border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700"
                            value={channel}
                            onChange={(e) => switchChannel(e.target.value)}
                        >
                            {channelList.map((ch) => (
                                <option key={ch} value={ch}>{ch}</option>
                            ))}
                        </select>
                    </div>
                </div>

                {activeTab === "search" ? (
                    <SearchTab
                        filteredRows={filteredRows}
                        stats={stats}
                        page={page}
                        totalPages={totalPages}
                        pageSize={pageSize}
                        applied={applied}
                        draft={draft}
                        setDraft={setDraft}
                        loading={loading}
                        error={error}
                        hasUnappliedChanges={hasUnappliedChanges}
                        resetDraftAndApply={resetDraftAndApply}
                        applyDraft={applyDraft}
                        runQuery={(p, size) => void runQuery(p, size)}
                        openDetail={(item) => void openDetail(item)}
                        query={query}
                    />
                ) : activeTab === "github" ? (
                    <GithubTab
                        depsStats={depsStats}
                        langsStats={langsStats}
                        statsLoading={statsLoading}
                        loadGithubStats={() => void loadGithubStats()}
                        pkgName={pkgName}
                        setPkgName={setPkgName}
                        pkgEco={pkgEco}
                        setPkgEco={setPkgEco}
                        pkgResults={pkgResults}
                        pkgLoading={pkgLoading}
                        pkgError={pkgError}
                        searchByPackage={() => void searchByPackage()}
                        langName={langName}
                        setLangName={setLangName}
                        langResults={langResults}
                        langLoading={langLoading}
                        langError={langError}
                        searchByLanguage={() => void searchByLanguage()}
                        topPackages={topPackages}
                        topLanguages={topLanguages}
                        topStatsLoading={topStatsLoading}
                        ecosystems={ecosystems}
                        topEco={topEco}
                        onEcoChange={(eco) => { setTopEco(eco); void loadTopPackages(eco || undefined); }}
                        cweStats={cweStats}
                        cweStatsLoading={cweStatsLoading}
                        loadCweStats={() => void loadCweStats()}
                    />
                ) : (
                    <DebugTab
                        cveId={cveId}
                        setCveId={setCveId}
                        maxPage={maxPage}
                        setMaxPage={setMaxPage}
                        retryPages={retryPages}
                        setRetryPages={setRetryPages}
                        retryResult={retryResult}
                        gaps={gaps}
                        checkpoints={checkpoints}
                        debugLoadByCve={() => void debugLoadByCve()}
                        debugLoadGaps={() => void debugLoadGaps()}
                        debugLoadCheckpoints={() => void debugLoadCheckpoints()}
                        debugRetryPages={() => void debugRetryPages()}
                    />
                )}
            </main>

            {selected ? (
                <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/50 backdrop-blur-sm" onClick={() => setSelected(null)}>
                    <aside className="h-full w-full max-w-[680px] overflow-auto border-l border-slate-200 bg-white shadow-2xl" onClick={(e) => e.stopPropagation()}>
                        <div className="sticky top-0 z-10 flex items-center justify-between border-b border-slate-200 bg-white/95 px-5 py-4">
                            <div>
                                <div className="text-xs uppercase tracking-widest text-slate-400">Vulnerability Detail</div>
                                <h3 className="text-xl font-semibold text-slate-950">{selected.cve_id}</h3>
                            </div>
                            <button className="rounded-full border border-slate-200 bg-slate-50 px-3 py-2 text-sm" onClick={() => setSelected(null)}>関闭</button>
                        </div>

                        <div className="space-y-4 p-5">
                            <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-4 space-y-2">
                                <LabeledLine label="标题" text={selected.title || "-"} />
                                <LabeledLine label="严重等级" text={selected.severity || "-"} />
                                <CollapsibleText label="简介" text={selected.description || "暂无描述"} lines={3} />
                                <div className="grid gap-2 md:grid-cols-2">
                                    <LabeledLine label="CWE" text={`${selected.cwe_id || "-"}${selected.cwe_description ? ` - ${selected.cwe_description}` : ""}`} />
                                    <LabeledLine label="CVSS" text={`${scoreText(selected.cvss_score)}${selected.cvss_vector ? ` | ${selected.cvss_vector}` : ""}`} mono />
                                </div>
                                <LabeledLine label="时间" text={`更新 ${selected.modified_date || "-"} / 发布 ${selected.published_date || "-"}`} />
                            </div>

                            {Object.keys(repoData).length > 0 && (
                                <div className="space-y-3">
                                    <div className="text-xs font-semibold uppercase tracking-widest text-slate-400">GitHub 仓库</div>
                                    {Object.entries(repoData).map(([key, data]) => (
                                        <GitHubRepoCard key={key} repoKey={key} data={data} />
                                    ))}
                                </div>
                            )}

                            <div className="rounded-xl bg-slate-950 p-4 text-white">
                                <div className="text-xs uppercase tracking-widest text-slate-400">JSON</div>
                                <pre className="mt-3 max-h-[560px] overflow-auto whitespace-pre-wrap break-words text-xs text-slate-100">{detailJson}</pre>
                            </div>
                        </div>
                    </aside>
                </div>
            ) : null}
        </div>
    );
}
