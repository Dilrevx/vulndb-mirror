"use client";
import { useState } from "react";

export function SummaryLine({ text }: { text: string }) {
    const [expanded, setExpanded] = useState(false);
    const canExpand = text.length > 140;
    return (
        <div className="flex items-end gap-1 text-sm text-slate-600">
            <span className={`min-w-0 flex-1 leading-6 ${expanded ? "" : "line-clamp-2"}`}>{text}</span>
            {canExpand ? <button className="shrink-0 text-xs text-blue-600" onClick={() => setExpanded((v) => !v)}>{expanded ? "收起" : "展开"}</button> : null}
        </div>
    );
}
