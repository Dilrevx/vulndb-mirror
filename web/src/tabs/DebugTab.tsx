"use client";
import type { GapsResp, CheckpointsResp } from "@/types";
import { DebugBlock } from "@/components/DebugBlock";

interface DebugTabProps {
    cveId: string;
    setCveId: (v: string) => void;
    maxPage: number;
    setMaxPage: (v: number) => void;
    retryPages: string;
    setRetryPages: (v: string) => void;
    retryResult: string;
    gaps: GapsResp | null;
    checkpoints: CheckpointsResp | null;
    debugLoadByCve: () => void;
    debugLoadGaps: () => void;
    debugLoadCheckpoints: () => void;
    debugRetryPages: () => void;
}

export function DebugTab({
    cveId, setCveId, maxPage, setMaxPage, retryPages, setRetryPages,
    retryResult, gaps, checkpoints,
    debugLoadByCve, debugLoadGaps, debugLoadCheckpoints, debugRetryPages,
}: DebugTabProps) {
    return (
        <section className="mt-4 space-y-4">
            <div className="rounded-xl border border-slate-200 bg-white px-4 py-3">
                <h2 className="text-sm font-semibold uppercase tracking-[0.25em] text-slate-600">Aliyun Debug</h2>
                <p className="mt-1 text-sm text-slate-500">用于补漏、覆盖检查、页重试与排障。</p>
            </div>

            <div className="grid gap-4 xl:grid-cols-3">
                <div className="rounded-xl border border-slate-200 bg-white p-4">
                    <h3 className="text-sm font-semibold">按 CVE 调试</h3>
                    <div className="mt-3 flex gap-2">
                        <input className="min-w-0 flex-1 rounded border border-slate-200 px-2 py-2 text-sm" value={cveId} onChange={(e) => setCveId(e.target.value)} placeholder="CVE-2026-xxxx" />
                        <button className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-xs" onClick={debugLoadByCve}>查询</button>
                    </div>
                </div>

                <div className="rounded-xl border border-slate-200 bg-white p-4">
                    <h3 className="text-sm font-semibold">覆盖检查</h3>
                    <div className="mt-3 flex gap-2">
                        <input className="min-w-0 flex-1 rounded border border-slate-200 px-2 py-2 text-sm" type="number" min={1} value={maxPage} onChange={(e) => setMaxPage(Number(e.target.value || 1))} />
                        <button className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-xs" onClick={debugLoadGaps}>gaps</button>
                        <button className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-xs" onClick={debugLoadCheckpoints}>checkpoints</button>
                    </div>
                </div>

                <div className="rounded-xl border border-slate-200 bg-white p-4">
                    <h3 className="text-sm font-semibold">页重试</h3>
                    <div className="mt-3 flex gap-2">
                        <input className="min-w-0 flex-1 rounded border border-slate-200 px-2 py-2 text-sm" value={retryPages} onChange={(e) => setRetryPages(e.target.value)} placeholder="50 51 52" />
                        <button className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-xs" onClick={debugRetryPages}>retry</button>
                    </div>
                </div>
            </div>

            <div className="grid gap-4 xl:grid-cols-3">
                <DebugBlock title="Gaps" text={gaps ? JSON.stringify(gaps, null, 2) : "暂无 gaps 数据"} />
                <DebugBlock title="Checkpoints" text={checkpoints ? JSON.stringify(checkpoints, null, 2) : "暂无 checkpoints 数据"} />
                <DebugBlock title="Retry 结果" text={retryResult} />
            </div>
        </section>
    );
}
