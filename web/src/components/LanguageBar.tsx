"use client";
import type { LangEntry } from "@/types";
import { LANG_COLORS } from "@/lib/utils";

export function LanguageBar({ languages }: { languages: LangEntry[] }) {
    if (!languages.length) return null;
    return (
        <div>
            <div className="flex h-2 w-full overflow-hidden rounded-full">
                {languages.map((l) => (
                    <div
                        key={l.language}
                        style={{ width: `${l.percent}%`, backgroundColor: LANG_COLORS[l.language] ?? "#8b949e" }}
                        title={`${l.language}: ${l.percent}%`}
                    />
                ))}
            </div>
            <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1">
                {languages.slice(0, 8).map((l) => (
                    <span key={l.language} className="flex items-center gap-1 text-[11px] text-slate-600">
                        <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: LANG_COLORS[l.language] ?? "#8b949e" }} />
                        {l.language}
                        <span className="text-slate-400">{l.percent}%</span>
                    </span>
                ))}
            </div>
        </div>
    );
}
