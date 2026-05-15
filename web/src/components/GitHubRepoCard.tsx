"use client";
import { useState } from "react";
import type { PkgEntry, RepoGithubData } from "@/types";
import { LanguageBar } from "./LanguageBar";

export function GitHubRepoCard({ repoKey, data }: { repoKey: string; data: RepoGithubData }) {
    const [pkgsExpanded, setPkgsExpanded] = useState(false);
    const [owner, repo] = repoKey.split("/");
    const langs = data.langs?.status === "fetched" ? (data.langs.languages ?? []) : [];
    const pkgs = data.deps?.status === "fetched" ? (data.deps.packages ?? []) : [];
    const pkgCount = data.deps?.package_count ?? pkgs.length;

    const ecosystems = Array.from(new Set(pkgs.map((p) => p.ecosystem ?? "other"))).sort();
    const pkgsByEco: Record<string, PkgEntry[]> = {};
    for (const p of pkgs) {
        const eco = p.ecosystem ?? "other";
        (pkgsByEco[eco] ??= []).push(p);
    }

    return (
        <div className="rounded-lg border border-slate-200 bg-slate-50/60 p-3 text-sm">
            <div className="flex items-center justify-between gap-2">
                <a
                    href={`https://github.com/${owner}/${repo}`}
                    target="_blank"
                    rel="noreferrer"
                    className="font-mono text-xs font-semibold text-blue-700 hover:underline"
                >
                    {owner}/{repo}
                </a>
                {data.loading && <span className="text-[11px] text-slate-400">加载中…</span>}
                {!data.loading && data.langs?.status && data.langs.status !== "fetched" && (
                    <span className="text-[11px] text-slate-400">{data.langs.status}</span>
                )}
            </div>

            {langs.length > 0 && (
                <div className="mt-2">
                    <LanguageBar languages={langs} />
                </div>
            )}

            {pkgCount > 0 && (
                <div className="mt-2">
                    <button
                        className="flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-700"
                        onClick={() => setPkgsExpanded((v) => !v)}
                    >
                        <span>{pkgsExpanded ? "▾" : "▸"}</span>
                        <span>{pkgCount} 个依赖包</span>
                    </button>
                    {pkgsExpanded && (
                        <div className="mt-2 space-y-2">
                            {ecosystems.map((eco) => (
                                <div key={eco}>
                                    <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">{eco}</div>
                                    <div className="mt-1 flex flex-wrap gap-1">
                                        {(pkgsByEco[eco] ?? []).map((p, i) => (
                                            <span
                                                key={i}
                                                className="rounded bg-white px-1.5 py-0.5 text-[11px] text-slate-700 ring-1 ring-slate-200"
                                                title={p.version_info ?? undefined}
                                            >
                                                {p.package_name}
                                                {p.version_info ? <span className="ml-1 text-slate-400">{p.version_info}</span> : null}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {!data.loading && pkgCount === 0 && langs.length === 0 && data.deps?.status && (
                <p className="mt-1 text-[11px] text-slate-400">
                    deps: {data.deps.status}{data.langs?.status ? ` · langs: ${data.langs.status}` : ""}
                </p>
            )}
        </div>
    );
}
