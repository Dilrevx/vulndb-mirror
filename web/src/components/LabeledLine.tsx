"use client";

export function LabeledLine({ label, text, mono = false }: { label: string; text: string; mono?: boolean }) {
    return (
        <p className="text-sm leading-6 text-slate-700">
            <strong className="font-semibold text-slate-900">{label}: </strong>
            <span className={mono ? "font-mono text-[13px]" : ""}>{text || "-"}</span>
        </p>
    );
}
