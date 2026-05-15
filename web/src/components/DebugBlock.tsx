"use client";

export function DebugBlock({ title, text }: { title: string; text: string }) {
    return (
        <div className="rounded-xl border border-slate-200 bg-white p-4">
            <h3 className="text-sm font-semibold">{title}</h3>
            <pre className="mt-3 max-h-72 overflow-auto rounded border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700">{text}</pre>
        </div>
    );
}
