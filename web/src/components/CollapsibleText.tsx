"use client";
import { useState } from "react";

export function CollapsibleText({ label, text, lines = 2 }: { label: string; text: string; lines?: number }) {
    const [expanded, setExpanded] = useState(false);
    const clampClass = lines === 1 ? "line-clamp-1" : lines === 2 ? "line-clamp-2" : "line-clamp-3";
    const canExpand = text.length > (lines === 1 ? 80 : lines === 2 ? 140 : 220);
    return (
        <div className="text-sm leading-6 text-slate-700">
            <div className="flex items-end gap-1">
                <strong className="font-semibold text-slate-900">{label}: </strong>
                <span className={`min-w-0 flex-1 ${expanded ? "" : clampClass}`}>{text}</span>
                {canExpand ? <button className="shrink-0 text-xs text-blue-600" onClick={() => setExpanded((v) => !v)}>{expanded ? "收起" : "展开"}</button> : null}
            </div>
        </div>
    );
}
