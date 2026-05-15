"use client";
import { useState } from "react";
import { trimUrl } from "@/lib/utils";

export function LinkLine({ title, urls }: { title: string; urls: string[] }) {
    const [expanded, setExpanded] = useState(false);
    const canExpand = urls.length > 4;
    return (
        <div>
            <div className="text-xs uppercase tracking-widest text-slate-500">{title}</div>
            {urls.length ? (
                <div className="mt-1 flex items-end gap-1">
                    <div className={`min-w-0 flex-1 text-xs leading-5 text-slate-700 ${expanded ? "" : "line-clamp-2"}`}>
                        {urls.map((url, index) => (
                            <span key={url}>
                                <a href={url} target="_blank" rel="noreferrer" className="underline decoration-slate-300 underline-offset-2 hover:text-blue-700" title={url}>
                                    {trimUrl(url)}
                                </a>
                                {index < urls.length - 1 ? <span className="mx-1 text-slate-400">·</span> : null}
                            </span>
                        ))}
                    </div>
                    {canExpand ? <button className="shrink-0 text-xs text-blue-600" onClick={() => setExpanded((v) => !v)}>{expanded ? "收起" : "展开"}</button> : null}
                </div>
            ) : (
                <p className="text-xs text-slate-500">-</p>
            )}
        </div>
    );
}
