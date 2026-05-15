export type RawItem = {
    cve_id: string;
    title?: string;
    description?: string;
    severity?: string;
    cvss_score?: number | null;
    cvss_vector?: string;
    cwe_id?: string;
    cwe_description?: string;
    published_date?: string | null;
    modified_date?: string | null;
    references?: string[];
    patch_urls?: string[];
    detail_url?: string;
};

export type QueryResp = {
    page: number;
    page_size: number;
    total: number;
    items: RawItem[];
};

export type CheckpointItem = {
    page: number;
    status: string;
    entry_count: number;
    has_next: boolean;
    error?: string | null;
    updated_at: string;
};

export type GapsResp = {
    gaps: Array<{ start_page: number; end_page: number; reason: string }>;
    meta: Record<string, unknown>;
};

export type CheckpointsResp = {
    items: CheckpointItem[];
    meta: Record<string, unknown>;
};

export type TabMode = "search" | "debug" | "github";
export type TriMode = "all" | "yes" | "no";
export type PoCRuleMode = "balanced" | "strict" | "loose";
export type ChannelId = string;

export type SmartSearchTokens = {
    text: string[];
    cve: string;
    cwe: string;
    severity: string;
    patch: TriMode;
    poc: TriMode;
};

export type FilterDraft = {
    search: string;
    patchOnly: TriMode;
    pocOnly: TriMode;
    refOnly: TriMode;
    detailOnly: TriMode;
    pocRuleMode: PoCRuleMode;
    showAdvanced: boolean;
    from: string;
    to: string;
};

export type LangEntry = { language: string; bytes: number; percent: number };
export type PkgEntry = {
    manifest_path: string | null;
    ecosystem: string | null;
    package_name: string;
    version_info: string | null;
    relationship: string | null;
};
export type GithubLangsData = { status: string; languages: LangEntry[] };
export type GithubDepsData = { status: string; package_count: number; packages: PkgEntry[] };
export type RepoGithubData = { langs: GithubLangsData | null; deps: GithubDepsData | null; loading: boolean };

export type PkgByPackageItem = {
    owner: string; repo: string; manifest_path: string | null;
    ecosystem: string | null; package_name: string; version_info: string | null;
    relationship: string | null; priority: number; source_cves: string[]; fetched_at: string | null;
};
export type LangByLanguageItem = {
    owner: string; repo: string; language: string; bytes: number;
    priority: number; source_cves: string[]; fetched_at: string | null;
};
