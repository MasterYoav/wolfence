export type RepoStatusTone = "safe" | "review" | "blocked";

export interface WorkspaceRepo {
  id: string;
  name: string;
  path: string;
  branch: string;
  upstream: string;
  verdict: string;
  summary: string;
  tone: RepoStatusTone;
}

export interface FindingItem {
  level: "critical" | "medium risk" | "low risk" | "info";
  location: string;
  title: string;
}

export const workspaceRepos: WorkspaceRepo[] = [
  {
    id: "wolfence",
    name: "Wolfence",
    path: "/Users/yoavperetz/Developer/Wolfence",
    branch: "main",
    upstream: "origin/main",
    verdict: "Push Ready",
    summary: "2 commits ahead • 18 files in scope",
    tone: "safe"
  },
  {
    id: "dragon",
    name: "Dragon",
    path: "/Users/yoavperetz/Developer/Dragon",
    branch: "main",
    upstream: "origin/main",
    verdict: "Warnings",
    summary: "1 warning • 6 files in scope",
    tone: "review"
  },
  {
    id: "sandbox",
    name: "Sandbox",
    path: "/Users/yoavperetz/Developer/Sandbox",
    branch: "feature/web-ui",
    upstream: "origin/feature/web-ui",
    verdict: "Blocked",
    summary: "2 blockers • 4 files in scope",
    tone: "blocked"
  }
];

export const blockers: FindingItem[] = [
  {
    level: "critical",
    location: "src/core/scanners.rs",
    title: "Scanner bundle changed without matching provenance update"
  },
  {
    level: "medium risk",
    location: ".github/workflows/release.yml",
    title: "Publish workflow is missing explicit provenance signals"
  }
];

export const warnings: FindingItem[] = [
  {
    level: "low risk",
    location: ".github/CODEOWNERS",
    title: "Release governance ownership should be reviewed"
  },
  {
    level: "info",
    location: ".wolfence/config.toml",
    title: "Repo exclusions are active for fixture repositories"
  }
];

export const doctorChecks = [
  {
    name: "Push remote",
    state: "Healthy",
    detail: "Remote configured and current upstream is reachable."
  },
  {
    name: "Managed hook",
    state: "Healthy",
    detail: "Native pre-push hook is installed and aligned with the local binary."
  },
  {
    name: "GitHub governance",
    state: "Review",
    detail: "Repo-as-code protections are readable, but release permissions need another pass."
  }
];

export const auditEntries = [
  {
    sequence: "#0042",
    outcome: "Allowed",
    detail: "Protected push completed after zero blockers and two warnings.",
    time: "11:42"
  },
  {
    sequence: "#0041",
    outcome: "Blocked",
    detail: "Policy stopped a scanner-bundle change until provenance was updated.",
    time: "10:18"
  },
  {
    sequence: "#0040",
    outcome: "Allowed",
    detail: "Doctor trust checks passed and the outbound scope was clean.",
    time: "09:03"
  }
];
