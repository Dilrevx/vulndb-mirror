"use client";
import { useEffect, useState } from "react";

export function PageControls({
    page,
    totalPages,
    pageSize,
    onPage,
    onPageSize,
}: {
    page: number;
    totalPages: number;
    pageSize: number;
    onPage: (page: number) => void;
    onPageSize: (size: number) => void;
}) {
    const [pageInput, setPageInput] = useState(String(page));

    useEffect(() => {
        setPageInput(String(page));
    }, [page]);

    function jumpToPage(): void {
        const parsed = Number(pageInput);
        if (!Number.isInteger(parsed)) return;
        onPage(Math.min(totalPages, Math.max(1, parsed)));
    }

    return (
        <div className="flex flex-wrap items-center gap-2">
            <button className="rounded border border-slate-200 bg-white px-2 py-1 text-xs disabled:cursor-not-allowed disabled:opacity-50" disabled={page <= 1} onClick={() => onPage(Math.max(1, page - 1))}>上一页</button>
            <button className="rounded border border-slate-200 bg-white px-2 py-1 text-xs disabled:cursor-not-allowed disabled:opacity-50" disabled={page >= totalPages} onClick={() => onPage(Math.min(totalPages, page + 1))}>下一页</button>
            <label className="flex items-center gap-1 rounded border border-slate-200 bg-white px-2 py-1 text-xs text-slate-600">
                <span>跳到</span>
                <input
                    className="w-16 border-0 bg-transparent p-0 text-center text-xs outline-none"
                    inputMode="numeric"
                    min={1}
                    max={totalPages}
                    type="number"
                    value={pageInput}
                    onChange={(e) => setPageInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter") jumpToPage(); }}
                />
                <span>/ {totalPages}</span>
            </label>
            <button className="rounded border border-slate-200 bg-white px-2 py-1 text-xs" onClick={jumpToPage}>前往</button>
            <select className="rounded border border-slate-200 bg-white px-2 py-1 text-xs" value={pageSize} onChange={(e) => onPageSize(Number(e.target.value))}>
                <option value={10}>10/页</option>
                <option value={20}>20/页</option>
                <option value={50}>50/页</option>
                <option value={100}>100/页</option>
            </select>
        </div>
    );
}
