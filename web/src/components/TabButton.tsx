"use client";

export function TabButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
    return (
        <button
            className={`rounded border px-3 py-1.5 text-xs font-medium ${active ? "border-blue-300 bg-blue-50 text-blue-700" : "border-slate-200 bg-white text-slate-600"}`}
            onClick={onClick}
        >
            {label}
        </button>
    );
}
