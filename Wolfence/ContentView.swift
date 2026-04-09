import AppKit
import Observation
import SwiftUI

struct ContentView: View {
    @AppStorage("workspaceRepositoryPaths") private var workspaceRepositoryPaths = "[]"
    @AppStorage("selectedRepositoryPath") private var selectedRepositoryPath = ""
    @AppStorage("sidebarCollapsed") private var sidebarCollapsed = false
    @State private var workspace = WorkspaceStore()
    private let shouldRestoreSelection: Bool

    @MainActor
    init() {
        shouldRestoreSelection = true
    }

    @MainActor
    fileprivate init(previewWorkspace: WorkspaceStore) {
        _workspace = State(initialValue: previewWorkspace)
        shouldRestoreSelection = false
    }

    private var activeRepository: WorkspaceRepository? {
        workspace.selectedRepository
    }

    private var activeMonitor: WolfenceMonitor? {
        activeRepository?.monitor
    }

    private var sidebarWidth: CGFloat {
        sidebarCollapsed ? 92 : 248
    }

    var body: some View {
        ZStack {
            WolfenceTheme.windowBackground
                .ignoresSafeArea()

            if workspace.repositories.isEmpty {
                onboardingState
                    .padding(28)
            } else {
                workspaceShell
            }
        }
        .frame(minWidth: 1380, minHeight: 880)
        .toolbarBackgroundVisibility(.hidden, for: .windowToolbar)
        .toolbar(removing: .title)
        .windowToolbarFullScreenVisibility(.onHover)
        .task {
            guard shouldRestoreSelection else { return }
            await restoreWorkspaceIfNeeded()
        }
    }

    private var onboardingState: some View {
        VStack(alignment: .leading, spacing: 30) {
            wolfHeaderMark(size: 86)

            VStack(alignment: .leading, spacing: 12) {
                Text("Wolfence")
                    .font(.system(size: 58, weight: .regular, design: .serif))
                    .foregroundStyle(WolfenceTheme.primaryInk)

                Text("Security-first Git desktop workspace")
                    .font(.system(size: 18, weight: .semibold, design: .rounded))
                    .foregroundStyle(WolfenceTheme.secondaryInk)

                Text("Pin multiple repositories in a permanent sidebar, inspect each push decision in place, and keep Git posture, trust readiness, and audit evidence visible at the same time.")
                    .font(.system(size: 16, weight: .medium, design: .rounded))
                    .foregroundStyle(WolfenceTheme.secondaryInk)
                    .frame(maxWidth: 720, alignment: .leading)
            }

            HStack(spacing: 14) {
                Button("Add Repository") {
                    addRepositoryFromPanel()
                }
                .buttonStyle(.borderedProminent)
                .tint(WolfenceTheme.action)

                Text("Start by adding one or more repositories. Each sidebar item becomes a full Wolfence console.")
                    .font(.system(size: 13, weight: .medium, design: .rounded))
                    .foregroundStyle(WolfenceTheme.mutedInk)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(52)
        .background(
            RoundedRectangle(cornerRadius: 34, style: .continuous)
                .fill(WolfenceTheme.surface)
                .overlay(
                    RoundedRectangle(cornerRadius: 34, style: .continuous)
                        .stroke(WolfenceTheme.rule, lineWidth: 1)
                )
        )
    }

    private var workspaceShell: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
                .overlay(WolfenceTheme.rule)
                .opacity(sidebarCollapsed ? 0.45 : 1)

            VStack(spacing: 0) {
                windowChrome
                detailArea
            }
        }
        .background(WolfenceTheme.surface.opacity(0.45))
        .clipShape(RoundedRectangle(cornerRadius: 0))
        .animation(.spring(response: 0.32, dampingFraction: 0.84), value: sidebarCollapsed)
        .ignoresSafeArea(edges: .top)
    }

    private var windowChrome: some View {
        HStack(spacing: 18) {
            VStack(alignment: .leading, spacing: 2) {
                Text(activeRepository?.displayTitle ?? "Workspace")
                    .font(.system(size: 24, weight: .regular, design: .serif))
                    .foregroundStyle(WolfenceTheme.primaryInk)

                Text("Wolfence security workspace")
                    .font(.system(size: 11, weight: .semibold, design: .rounded))
                    .foregroundStyle(WolfenceTheme.mutedInk)
                    .textCase(.uppercase)
            }

            Spacer(minLength: 20)

            if let monitor = activeMonitor {
                VStack(alignment: .trailing, spacing: 3) {
                    Text(monitor.pushSummaryLine)
                        .font(.system(size: 13, weight: .semibold, design: .rounded))
                        .foregroundStyle(WolfenceTheme.primaryInk)

                    Text(monitor.lastUpdatedLine)
                        .font(.system(size: 11, weight: .medium, design: .rounded))
                        .foregroundStyle(WolfenceTheme.mutedInk)
                }
                .frame(maxWidth: 360, alignment: .trailing)
            }

            HStack(spacing: 10) {
                Button {
                    Task { await workspace.refreshSelectedRepository() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.borderless)
                .disabled(activeMonitor == nil || (activeMonitor?.isRefreshing ?? false))

                Button {
                    Task { await workspace.refreshAllRepositories() }
                } label: {
                    Image(systemName: "arrow.triangle.2.circlepath")
                }
                .buttonStyle(.borderless)
                .disabled(workspace.repositories.isEmpty)
            }
            .foregroundStyle(WolfenceTheme.primaryInk)
        }
        .padding(.leading, 18)
        .padding(.trailing, 26)
        .padding(.top, 14)
        .padding(.bottom, 14)
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Color.clear
                    .frame(width: 54, height: 14)

                Button {
                    sidebarCollapsed.toggle()
                } label: {
                    Image(systemName: sidebarCollapsed ? "sidebar.right" : "sidebar.left")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(WolfenceTheme.primaryInk)
                        .frame(width: 32, height: 32)
                        .background(
                            RoundedRectangle(cornerRadius: 10, style: .continuous)
                                .fill(Color.white.opacity(0.22))
                        )
                }
                .buttonStyle(.plain)

                Spacer(minLength: 0)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 10)
            .padding(.bottom, sidebarCollapsed ? 14 : 12)
            .padding(.leading, 10)

            HStack(spacing: 10) {
                wolfHeaderMark(size: sidebarCollapsed ? 60 : 38)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

                if !sidebarCollapsed {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Wolfence")
                            .font(.system(size: 18, weight: .semibold, design: .serif))
                            .foregroundStyle(WolfenceTheme.primaryInk)
                        Text("Repository Gate")
                            .font(.system(size: 11, weight: .medium, design: .rounded))
                            .foregroundStyle(WolfenceTheme.mutedInk)
                    }
                }

                if !sidebarCollapsed {
                    Spacer(minLength: 0)
                }
            }
            .frame(maxWidth: .infinity, alignment: sidebarCollapsed ? .center : .leading)
            .padding(.bottom, 8)

            if !sidebarCollapsed {
                Text("\(workspace.repositories.count) workspaces")
                    .font(.system(size: 10, weight: .bold, design: .rounded))
                    .foregroundStyle(WolfenceTheme.mutedInk)
                    .textCase(.uppercase)
                    .padding(.top, 16)
                    .padding(.bottom, 8)
            }

            ScrollView {
                VStack(spacing: 8) {
                    ForEach(workspace.repositories) { repository in
                        SidebarRepositoryRow(
                            repository: repository,
                            isSelected: repository.id == workspace.selectedRepositoryID,
                            isCollapsed: sidebarCollapsed,
                            onSelect: {
                                workspace.selectRepository(id: repository.id)
                                persistWorkspace()
                            },
                            onRemove: {
                                workspace.removeRepository(id: repository.id)
                                persistWorkspace()
                            }
                        )
                    }
                }
                .padding(.horizontal, 12)
                .padding(.bottom, 14)
            
            }
            .scrollIndicators(.hidden)

            Spacer()

            VStack(alignment: .leading, spacing: 6) {
                SidebarActionButton(
                    title: "Add Repository",
                    icon: "plus",
                    collapsed: sidebarCollapsed,
                    isSelected: false,
                    themeColor: WolfenceTheme.action
                ) {
                    addRepositoryFromPanel()
                }

                SidebarActionButton(
                    title: "Refresh All",
                    icon: "arrow.triangle.2.circlepath",
                    collapsed: sidebarCollapsed,
                    isSelected: false,
                    themeColor: WolfenceTheme.navy
                ) {
                    Task { await workspace.refreshAllRepositories() }
                }
            }
            .frame(maxWidth: .infinity, alignment: sidebarCollapsed ? .center : .leading)
            .padding(.bottom, sidebarCollapsed ? 0 : 10)
        }
        .padding(.horizontal, sidebarCollapsed ? 10 : 12)
        .padding(.bottom, 10)
        .frame(width: sidebarWidth)
        .frame(maxHeight: .infinity)
        .background(
            Rectangle()
                .fill(
                    LinearGradient(
                        colors: [
                            Color.white.opacity(0.22),
                            Color.white.opacity(0.14)
                        ],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
                .overlay {
                    LinearGradient(
                        colors: [
                            Color.white.opacity(0.34),
                            WolfenceTheme.action.opacity(0.05),
                            Color.clear
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                }
        )
        .overlay(alignment: .trailing) {
            Rectangle()
                .fill(Color.white.opacity(0.3))
                .frame(width: 1)
        }
    }

    private var detailArea: some View {
        Group {
            if let repository = activeRepository, let monitor = activeMonitor {
                ScrollView {
                    VStack(alignment: .leading, spacing: 22) {
                        repoHeroPanel(repository: repository, monitor: monitor)
                        statusGrid(monitor: monitor)
                        detailGrid(monitor: monitor)
                        auditPanel(monitor: monitor)
                    }
                    .padding(24)
                    .padding(.bottom, 24)
                }
                .scrollIndicators(.hidden)
            } else {
                unavailableState(
                    title: "Select a repository",
                    detail: "Choose a repository from the sidebar or add one to start inspecting its push posture."
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(36)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func repoHeroPanel(repository: WorkspaceRepository, monitor: WolfenceMonitor) -> some View {
        SurfacePanel {
            HStack(alignment: .top, spacing: 24) {
                VStack(alignment: .leading, spacing: 18) {
                    HStack(alignment: .top, spacing: 18) {
                        repoMonogram(for: repository)

                        VStack(alignment: .leading, spacing: 7) {
                            Text(repository.displayTitle)
                                .font(.system(size: 40, weight: .regular, design: .serif))
                                .foregroundStyle(WolfenceTheme.primaryInk)

                            Text(repository.path)
                                .font(.system(size: 12, weight: .medium, design: .monospaced))
                                .foregroundStyle(WolfenceTheme.mutedInk)
                                .textSelection(.enabled)

                            Text("Git desktop, repository gate, and local security console in one persistent workspace.")
                                .font(.system(size: 14, weight: .medium, design: .rounded))
                                .foregroundStyle(WolfenceTheme.secondaryInk)
                        }
                    }

                    Divider()
                        .overlay(WolfenceTheme.rule)

                    HStack(spacing: 12) {
                        Button {
                            Task { await repository.monitor.refresh() }
                        } label: {
                            Label(repository.monitor.isRefreshing ? "Refreshing…" : "Refresh Repo", systemImage: "arrow.clockwise")
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(WolfenceTheme.action)

                        Button("Reveal in Finder") {
                            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: repository.path)])
                        }
                        .buttonStyle(.bordered)

                        Button("Copy Path") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(repository.path, forType: .string)
                        }
                        .buttonStyle(.bordered)
                    }
                }

                Spacer(minLength: 24)

                VStack(alignment: .trailing, spacing: 16) {
                    VStack(alignment: .trailing, spacing: 8) {
                        Text(monitor.heroTitle)
                            .font(.system(size: 32, weight: .semibold, design: .serif))
                            .foregroundStyle(monitor.heroColor)
                            .multilineTextAlignment(.trailing)

                        Text(monitor.heroSubtitle)
                            .font(.system(size: 14, weight: .medium, design: .rounded))
                            .foregroundStyle(WolfenceTheme.secondaryInk)
                            .multilineTextAlignment(.trailing)
                    }

                    VStack(alignment: .trailing, spacing: 4) {
                        Text(monitor.branchLine)
                            .font(.system(size: 14, weight: .semibold, design: .rounded))
                            .foregroundStyle(WolfenceTheme.primaryInk)

                        Text(monitor.pushSummaryLine)
                            .font(.system(size: 12, weight: .medium, design: .rounded))
                            .foregroundStyle(WolfenceTheme.mutedInk)
                    }
                }
                .frame(maxWidth: 360, alignment: .trailing)
            }
        }
    }

    private func statusGrid(monitor: WolfenceMonitor) -> some View {
        HStack(spacing: 18) {
            MetricPanel(title: "Push Decision", value: monitor.pushDecisionValue, detail: monitor.pushDecisionDetail, tone: monitor.heroColor)
            MetricPanel(title: "Trust Posture", value: monitor.doctorValue, detail: monitor.doctorDetail, tone: monitor.doctorTone)
            MetricPanel(title: "Audit Chain", value: "\(monitor.auditEntries.count)", detail: monitor.auditDetail, tone: WolfenceTheme.navy)
            MetricPanel(title: "Policy Mode", value: monitor.policyModeDisplay, detail: monitor.policyModeDetail, tone: WolfenceTheme.steel)
        }
    }

    private func detailGrid(monitor: WolfenceMonitor) -> some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 380), spacing: 18)], spacing: 18) {
            pushPanel(monitor: monitor)
            doctorPanel(monitor: monitor)
            policyPanel(monitor: monitor)
            findingsPanel(monitor: monitor)
            scanScopePanel(monitor: monitor)
            receiptsPanel(monitor: monitor)
        }
    }

    private func pushPanel(monitor: WolfenceMonitor) -> some View {
        SurfacePanel(title: "Push Posture", subtitle: "Primary decision surface") {
            VStack(alignment: .leading, spacing: 16) {
                InfoRow(label: "Verdict", value: monitor.pushDecisionValue)
                InfoRow(label: "Scope", value: monitor.pushScopeDescription)
                InfoRow(label: "Branch", value: monitor.branchLine)
                InfoRow(label: "Execution", value: monitor.pushExecutionDetail)

                if let detail = monitor.scanDetailLine {
                    Divider()
                        .overlay(WolfenceTheme.rule)
                    Text(detail)
                        .font(.system(size: 13, weight: .medium, design: .rounded))
                        .foregroundStyle(WolfenceTheme.secondaryInk)
                }
            }
        }
    }

    private func doctorPanel(monitor: WolfenceMonitor) -> some View {
        SurfacePanel(title: "Local Trust", subtitle: "Doctor summary and weak points") {
            VStack(alignment: .leading, spacing: 16) {
                if let doctor = monitor.doctorReport {
                    Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 10) {
                        GridRow {
                            summaryValue("Pass", value: doctor.summary.pass, tone: WolfenceTheme.ok)
                            summaryValue("Warn", value: doctor.summary.warn, tone: WolfenceTheme.caution)
                            summaryValue("Fail", value: doctor.summary.fail, tone: WolfenceTheme.alert)
                            summaryValue("Info", value: doctor.summary.info, tone: WolfenceTheme.steel)
                        }
                    }

                    Divider()
                        .overlay(WolfenceTheme.rule)

                    VStack(alignment: .leading, spacing: 12) {
                        ForEach(monitor.priorityChecks) { check in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(check.name.capitalized)
                                    .font(.system(size: 14, weight: .semibold, design: .rounded))
                                    .foregroundStyle(WolfenceTheme.primaryInk)

                                Text(check.detail)
                                    .font(.system(size: 12, weight: .medium, design: .rounded))
                                    .foregroundStyle(WolfenceTheme.secondaryInk)

                                if let remediation = check.remediation {
                                    Text(remediation)
                                        .font(.system(size: 12, weight: .medium, design: .rounded))
                                        .foregroundStyle(WolfenceTheme.mutedInk)
                                }
                            }
                            if check.id != monitor.priorityChecks.last?.id {
                                Divider()
                                    .overlay(WolfenceTheme.rule.opacity(0.65))
                            }
                        }
                    }
                } else {
                    unavailableState(
                        title: "Doctor output unavailable",
                        detail: "Wolfence doctor JSON could not be loaded for this repository."
                    )
                }
            }
        }
    }

    private func policyPanel(monitor: WolfenceMonitor) -> some View {
        SurfacePanel(title: "Policy Surface", subtitle: "Repo-local enforcement defaults") {
            VStack(alignment: .leading, spacing: 16) {
                InfoRow(label: "Mode", value: monitor.policyModeDisplay)
                InfoRow(label: "Source", value: monitor.modeSourceDisplay)
                InfoRow(label: "Ignored Paths", value: monitor.ignorePathsDisplay)
                InfoRow(label: "Receipt Signatures", value: monitor.signaturePolicyDisplay)
                InfoRow(label: "Reviewer Metadata", value: monitor.reviewerPolicyDisplay)
                InfoRow(label: "Allowed Approvers", value: monitor.approverDisplay)
            }
        }
    }

    private func findingsPanel(monitor: WolfenceMonitor) -> some View {
        SurfacePanel(title: "Findings & Exceptions", subtitle: "Active push preview evidence") {
            VStack(alignment: .leading, spacing: 16) {
                if let scan = monitor.pushPreview {
                    InfoRow(label: "Findings", value: "\(scan.report?.findings.count ?? 0)")
                    InfoRow(label: "Blocking Findings", value: "\(scan.decision?.blockingFindings.count ?? 0)")
                    InfoRow(label: "Warning Findings", value: "\(scan.decision?.warningFindings.count ?? 0)")
                    InfoRow(label: "Overrides Applied", value: "\(scan.receipts.overridesApplied)")
                    InfoRow(label: "Receipt Issues", value: "\(scan.receipts.issueCount)")

                    if let topFinding = (scan.decision?.blockingFindings.first?.finding ?? scan.decision?.warningFindings.first?.finding) {
                        Divider()
                            .overlay(WolfenceTheme.rule)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(topFinding.title)
                                .font(.system(size: 14, weight: .semibold, design: .rounded))
                                .foregroundStyle(WolfenceTheme.primaryInk)
                            Text(topFinding.detail)
                                .font(.system(size: 12, weight: .medium, design: .rounded))
                                .foregroundStyle(WolfenceTheme.secondaryInk)
                        }
                    }
                } else {
                    unavailableState(
                        title: "No push preview",
                        detail: "The current repository has not produced structured push-preview data."
                    )
                }
            }
        }
    }

    private func scanScopePanel(monitor: WolfenceMonitor) -> some View {
        SurfacePanel(title: "Candidate Scope", subtitle: "Files entering the gate") {
            VStack(alignment: .leading, spacing: 14) {
                if let scope = monitor.pushPreview?.scanScope {
                    InfoRow(label: "Discovered", value: "\(scope.discoveredFiles)")
                    InfoRow(label: "Scanned", value: "\(scope.scannedFiles)")
                    InfoRow(label: "Ignored", value: "\(scope.ignoredFiles)")

                    Divider()
                        .overlay(WolfenceTheme.rule)

                    Text("Included Paths")
                        .font(.system(size: 13, weight: .semibold, design: .rounded))
                        .foregroundStyle(WolfenceTheme.primaryInk)

                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(scope.scannedPaths.prefix(8), id: \.self) { path in
                            Text(path)
                                .font(.system(size: 11, weight: .medium, design: .monospaced))
                                .foregroundStyle(WolfenceTheme.secondaryInk)
                        }
                    }
                } else {
                    unavailableState(
                        title: "No candidate scope",
                        detail: "Current push status is not in a ready state."
                    )
                }
            }
        }
    }

    private func receiptsPanel(monitor: WolfenceMonitor) -> some View {
        SurfacePanel(title: "Receipts & Governance", subtitle: "Exception controls") {
            VStack(alignment: .leading, spacing: 16) {
                InfoRow(label: "Require Signatures", value: monitor.signaturePolicyDisplay)
                InfoRow(label: "Require Reviewer", value: monitor.reviewerPolicyDisplay)
                InfoRow(label: "Explicit Category", value: monitor.explicitCategoryDisplay)
                InfoRow(label: "Allowed Reviewers", value: monitor.reviewerDisplay)
                InfoRow(label: "Allowed Key IDs", value: monitor.keyIDDisplay)
            }
        }
    }

    private func auditPanel(monitor: WolfenceMonitor) -> some View {
        SurfacePanel(title: "Audit Timeline", subtitle: "Chained local evidence") {
            VStack(alignment: .leading, spacing: 0) {
                if monitor.auditEntries.isEmpty {
                    unavailableState(
                        title: "No audit entries",
                        detail: "No chained audit decisions were found in `.wolfence/audit/decisions.jsonl`."
                    )
                } else {
                    ForEach(Array(monitor.auditEntries.prefix(10).enumerated()), id: \.element.id) { index, entry in
                        HStack(alignment: .top, spacing: 18) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("#\(entry.sequence)")
                                    .font(.system(size: 14, weight: .semibold, design: .rounded))
                                    .foregroundStyle(WolfenceTheme.primaryInk)

                                Text(entry.timestampLabel)
                                    .font(.system(size: 11, weight: .medium, design: .rounded))
                                    .foregroundStyle(WolfenceTheme.mutedInk)
                            }
                            .frame(width: 120, alignment: .leading)

                            VStack(alignment: .leading, spacing: 4) {
                                Text(entry.outcomeSummary)
                                    .font(.system(size: 14, weight: .semibold, design: .rounded))
                                    .foregroundStyle(entry.tone)

                                Text(entry.contextLine)
                                    .font(.system(size: 12, weight: .medium, design: .rounded))
                                    .foregroundStyle(WolfenceTheme.secondaryInk)

                                if let detail = entry.detail, !detail.isEmpty {
                                    Text(detail)
                                        .font(.system(size: 12, weight: .medium, design: .rounded))
                                        .foregroundStyle(WolfenceTheme.mutedInk)
                                }
                            }

                            Spacer(minLength: 0)

                            VStack(alignment: .trailing, spacing: 4) {
                                Text(entry.countsLine)
                                    .font(.system(size: 12, weight: .medium, design: .rounded))
                                    .foregroundStyle(WolfenceTheme.secondaryInk)

                                if let verdict = entry.verdict {
                                    Text(verdict.capitalized)
                                        .font(.system(size: 12, weight: .semibold, design: .rounded))
                                        .foregroundStyle(entry.tone)
                                }
                            }
                        }
                        .padding(.vertical, 14)

                        if index < min(monitor.auditEntries.count, 10) - 1 {
                            Divider()
                                .overlay(WolfenceTheme.rule)
                        }
                    }
                }
            }
        }
    }

    private func summaryValue(_ title: String, value: Int, tone: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title.uppercased())
                .font(.system(size: 10, weight: .bold, design: .rounded))
                .foregroundStyle(WolfenceTheme.mutedInk)
            Text("\(value)")
                .font(.system(size: 28, weight: .semibold, design: .serif))
                .foregroundStyle(tone)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func unavailableState(title: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 14, weight: .semibold, design: .rounded))
                .foregroundStyle(WolfenceTheme.primaryInk)
            Text(detail)
                .font(.system(size: 12, weight: .medium, design: .rounded))
                .foregroundStyle(WolfenceTheme.secondaryInk)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func wolfHeaderMark(size: CGFloat) -> some View {
        Image(nsImage: NSApp.applicationIconImage)
            .resizable()
            .scaledToFit()
            .frame(width: size, height: size)
            .shadow(color: WolfenceTheme.navy.opacity(0.18), radius: 18, y: 8)
    }

    private func repoMonogram(for repository: WorkspaceRepository) -> some View {
        ZStack {
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [repository.monitor.heroColor.opacity(0.28), Color.white.opacity(0.6)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
            Text(repository.shortName.prefix(2).uppercased())
                .font(.system(size: 22, weight: .bold, design: .rounded))
                .foregroundStyle(WolfenceTheme.primaryInk)
        }
        .frame(width: 64, height: 64)
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .stroke(WolfenceTheme.rule, lineWidth: 1)
        )
    }

    private func restoreWorkspaceIfNeeded() async {
        let storedPaths = decodeStoredPaths(workspaceRepositoryPaths)

        if storedPaths.isEmpty {
            let fallback = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            guard FileManager.default.fileExists(atPath: fallback.path) else { return }
            await workspace.restore(paths: [fallback.path], selectedID: fallback.path)
            selectedRepositoryPath = fallback.path
            persistWorkspace()
            return
        }

        await workspace.restore(paths: storedPaths, selectedID: selectedRepositoryPath)
        if workspace.selectedRepositoryID == nil {
            selectedRepositoryPath = workspace.selectedRepositoryID ?? ""
        }
        persistWorkspace()
    }

    private func addRepositoryFromPanel() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Add Repository"

        if panel.runModal() == .OK, let url = panel.url {
            Task {
                await workspace.addRepository(url)
                selectedRepositoryPath = workspace.selectedRepositoryID ?? url.path
                persistWorkspace()
            }
        }
    }

    private func persistWorkspace() {
        workspaceRepositoryPaths = encodeStoredPaths(workspace.repositories.map(\.path))
        selectedRepositoryPath = workspace.selectedRepositoryID ?? ""
    }

    private func decodeStoredPaths(_ rawValue: String) -> [String] {
        guard let data = rawValue.data(using: .utf8) else { return [] }
        return (try? JSONDecoder().decode([String].self, from: data)) ?? []
    }

    private func encodeStoredPaths(_ paths: [String]) -> String {
        guard let data = try? JSONEncoder().encode(Array(Set(paths)).sorted()),
              let string = String(data: data, encoding: .utf8) else {
            return "[]"
        }
        return string
    }
}

@Observable
@MainActor
private final class WorkspaceStore {
    private(set) var repositories: [WorkspaceRepository] = []
    private(set) var selectedRepositoryID: String?

    var selectedRepository: WorkspaceRepository? {
        repositories.first(where: { $0.id == selectedRepositoryID })
    }

    func restore(paths: [String], selectedID: String?) async {
        let uniquePaths = Array(Set(paths)).sorted()
        repositories = uniquePaths.map { WorkspaceRepository(path: $0) }
        selectedRepositoryID = selectedID.flatMap { id in
            repositories.contains(where: { $0.id == id }) ? id : repositories.first?.id
        } ?? repositories.first?.id

        await refreshAllRepositories()
    }

    func addRepository(_ url: URL) async {
        let path = url.path
        if repositories.contains(where: { $0.id == path }) {
            selectedRepositoryID = path
            return
        }

        let repository = WorkspaceRepository(path: path)
        repositories.append(repository)
        repositories.sort { $0.displayTitle.localizedCaseInsensitiveCompare($1.displayTitle) == .orderedAscending }
        selectedRepositoryID = path
        await repository.monitor.refresh()
    }

    func removeRepository(id: String) {
        repositories.removeAll { $0.id == id }
        if selectedRepositoryID == id {
            selectedRepositoryID = repositories.first?.id
        }
    }

    func selectRepository(id: String) {
        selectedRepositoryID = id
    }

    func refreshSelectedRepository() async {
        await selectedRepository?.monitor.refresh()
    }

    func refreshAllRepositories() async {
        for repository in repositories {
            await repository.monitor.refresh()
        }
    }

    static var preview: WorkspaceStore {
        let store = WorkspaceStore()
        store.repositories = [
            WorkspaceRepository(path: "/Users/yoavperetz/Developer/Wolfence", monitor: .preview),
            WorkspaceRepository(path: "/Users/yoavperetz/Developer/Dragon", monitor: .previewSecondary)
        ]
        store.selectedRepositoryID = store.repositories.first?.id
        return store
    }
}

@Observable
@MainActor
private final class WorkspaceRepository: Identifiable {
    let id: String
    let path: String
    let monitor: WolfenceMonitor

    init(path: String, monitor: WolfenceMonitor? = nil) {
        self.id = path
        self.path = path
        if let monitor {
            self.monitor = monitor
        } else {
            let createdMonitor = WolfenceMonitor()
            createdMonitor.setRepository(URL(fileURLWithPath: path))
            self.monitor = createdMonitor
        }
    }

    var shortName: String {
        URL(fileURLWithPath: path).lastPathComponent
    }

    var displayTitle: String {
        monitor.repositoryURL?.lastPathComponent ?? shortName
    }
}

private struct SidebarRepositoryRow: View {
    let repository: WorkspaceRepository
    let isSelected: Bool
    let isCollapsed: Bool
    let onSelect: () -> Void
    let onRemove: () -> Void

    var body: some View {
        Button(action: onSelect) {
            HStack(spacing: 10) {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(
                        isSelected
                            ? repository.monitor.heroColor.opacity(0.95)
                            : Color.white.opacity(0.22)
                    )
                    .frame(width: isCollapsed ? 48 : 22, height: isCollapsed ? 48 : 22)
                    .overlay(
                        Text(repository.shortName.prefix(2).uppercased())
                            .font(.system(size: isCollapsed ? 13 : 10, weight: .bold, design: .rounded))
                            .foregroundStyle(isSelected ? Color.white : WolfenceTheme.primaryInk)
                    )

                if !isCollapsed {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(repository.displayTitle)
                            .font(.system(size: 13, weight: .semibold, design: .rounded))
                            .foregroundStyle(isSelected ? Color.white : WolfenceTheme.primaryInk)
                            .lineLimit(1)

                        Text(repository.monitor.pushSummaryLine)
                            .font(.system(size: 10, weight: .medium, design: .rounded))
                            .foregroundStyle(isSelected ? Color.white.opacity(0.78) : WolfenceTheme.secondaryInk)
                            .lineLimit(2)
                    }

                    Spacer(minLength: 0)
                }
            }
            .padding(.horizontal, isCollapsed ? 0 : 12)
            .padding(.vertical, isCollapsed ? 0 : 9)
            .frame(
                maxWidth: isCollapsed ? 48 : .infinity,
                minHeight: isCollapsed ? 48 : nil,
                alignment: isCollapsed ? .center : .leading
            )
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(
                        isSelected
                            ? repository.monitor.heroColor.opacity(0.92)
                            : Color.white.opacity(0.18)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .stroke(
                                isSelected ? Color.white.opacity(0.16) : Color.white.opacity(0.26),
                                lineWidth: 1
                            )
                    )
            )
        }
        .buttonStyle(.plain)
        .help(repository.displayTitle)
        .contextMenu {
            Button("Reveal in Finder") {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: repository.path)])
            }
            Button("Remove Repository") {
                onRemove()
            }
        }
    }
}

private struct SidebarActionButton: View {
    let title: String
    let icon: String
    let collapsed: Bool
    let isSelected: Bool
    let themeColor: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .font(.system(size: 14, weight: .bold))
                    .frame(width: 18)

                if !collapsed {
                    Text(title)
                        .font(.system(size: 13, weight: .semibold, design: .rounded))
                    Spacer(minLength: 0)
                }
            }
            .foregroundStyle(isSelected ? Color.white : WolfenceTheme.primaryInk)
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .frame(
                maxWidth: collapsed ? 48 : .infinity,
                minHeight: collapsed ? 48 : nil,
                alignment: collapsed ? .center : .leading
            )
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(
                        isSelected
                            ? themeColor.opacity(0.96)
                            : Color.white.opacity(0.18)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .stroke(
                                isSelected ? Color.white.opacity(0.16) : Color.white.opacity(0.26),
                                lineWidth: 1
                            )
                    )
            )
        }
        .buttonStyle(.plain)
    }
}

@Observable
@MainActor
private final class WolfenceMonitor {
    private(set) var repositoryURL: URL?
    private(set) var doctorReport: DoctorReport?
    private(set) var pushPreview: PushPreviewReport?
    private(set) var repoConfiguration = RepoConfiguration()
    private(set) var receiptPolicy = ReceiptPolicy()
    private(set) var auditEntries: [AuditEntry] = []
    private(set) var isRefreshing = false
    private(set) var errorMessage: String?
    private(set) var lastUpdated = Date()

    var heroTitle: String {
        if errorMessage != nil {
            return "Console Needs Attention"
        }

        switch pushPreview?.decision?.verdict {
        case .block:
            return "Push Blocked"
        case .warn:
            return "Push Allowed With Warnings"
        case .allow:
            return "Push Ready"
        case .none:
            return "Awaiting Structured State"
        }
    }

    var heroSubtitle: String {
        if let errorMessage {
            return errorMessage
        }

        if let doctorReport, doctorReport.summary.fail > 0 {
            return "Local enforcement trust is degraded and should be corrected before relying on the gate."
        }

        if let preview = pushPreview {
            switch preview.status {
            case .ready:
                return "The outbound candidate set has been evaluated against repo policy."
            case .upToDate:
                return "No outbound work is pending; the gate has nothing to evaluate."
            case .noCommits:
                return "There are no commits ahead of the current upstream."
            case .completed:
                return "The protected push path completed successfully."
            case .error:
                return preview.error?.message ?? "Structured output returned an error."
            }
        }

        return "No push-preview JSON is available for the selected repository."
    }

    var heroColor: Color {
        if errorMessage != nil {
            return WolfenceTheme.alert
        }

        switch pushPreview?.decision?.verdict {
        case .block:
            return WolfenceTheme.alert
        case .warn:
            return WolfenceTheme.caution
        case .allow:
            return WolfenceTheme.ok
        case .none:
            return WolfenceTheme.navy
        }
    }

    var pushDecisionValue: String {
        if let errorMessage, !errorMessage.isEmpty {
            return "Unavailable"
        }

        guard let preview = pushPreview else { return "Unknown" }
        switch preview.status {
        case .noCommits:
            return "No Commits"
        case .upToDate:
            return "Up To Date"
        case .completed:
            return "Completed"
        case .ready:
            return preview.decision?.verdict.displayName ?? "Ready"
        case .error:
            return "Error"
        }
    }

    var pushDecisionDetail: String {
        if let preview = pushPreview {
            return preview.outcomeDetail
        }
        return errorMessage ?? "Refresh to load a current push-preview state."
    }

    var doctorValue: String {
        guard let doctorReport else { return "Unknown" }
        if doctorReport.summary.fail > 0 { return "Failing" }
        if doctorReport.summary.warn > 0 { return "Needs Review" }
        return "Healthy"
    }

    var doctorDetail: String {
        guard let doctorReport else { return "Doctor state unavailable" }
        return "\(doctorReport.summary.pass) pass, \(doctorReport.summary.warn) warn, \(doctorReport.summary.fail) fail"
    }

    var doctorTone: Color {
        guard let doctorReport else { return WolfenceTheme.steel }
        if doctorReport.summary.fail > 0 { return WolfenceTheme.alert }
        if doctorReport.summary.warn > 0 { return WolfenceTheme.caution }
        return WolfenceTheme.ok
    }

    var auditDetail: String {
        if let entry = auditEntries.first {
            return "Latest entry \(entry.outcomeSummary.lowercased())"
        }
        return "No chained evidence loaded"
    }

    var policyModeDisplay: String {
        repoConfiguration.policyMode?.capitalized ?? pushPreview?.mode?.capitalized ?? "Unset"
    }

    var policyModeDetail: String {
        if let mode = repoConfiguration.policyMode {
            return "\(mode.capitalized) mode from repo-local configuration"
        }
        return "Resolved from command output when available"
    }

    var modeSourceDisplay: String {
        pushPreview?.modeSource?.replacingOccurrences(of: "-", with: " ").capitalized ?? "Unknown"
    }

    var ignorePathsDisplay: String {
        repoConfiguration.ignorePaths.isEmpty ? "None" : repoConfiguration.ignorePaths.joined(separator: ", ")
    }

    var signaturePolicyDisplay: String {
        receiptPolicy.requireSignedReceipts ? "Required" : "Not Required"
    }

    var reviewerPolicyDisplay: String {
        receiptPolicy.requireReviewerMetadata ? "Required" : "Not Required"
    }

    var explicitCategoryDisplay: String {
        receiptPolicy.requireExplicitCategory ? "Required" : "Optional"
    }

    var reviewerDisplay: String {
        receiptPolicy.allowedReviewers.isEmpty ? "Any reviewer" : receiptPolicy.allowedReviewers.joined(separator: ", ")
    }

    var approverDisplay: String {
        receiptPolicy.allowedApprovers.isEmpty ? "Any approver" : receiptPolicy.allowedApprovers.joined(separator: ", ")
    }

    var keyIDDisplay: String {
        receiptPolicy.allowedKeyIDs.isEmpty ? "Any trusted key" : receiptPolicy.allowedKeyIDs.joined(separator: ", ")
    }

    var pushSummaryLine: String {
        guard let preview = pushPreview else { return "No push preview loaded" }
        switch preview.status {
        case .ready:
            return "\(preview.decision?.verdict.displayName ?? "Ready") • \(preview.commitsAhead ?? 0) commit ahead • \(preview.scanScope?.scannedFiles ?? 0) files in scope"
        case .upToDate:
            return "Up to date • no outbound scope"
        case .noCommits:
            return "No commits ahead of upstream"
        case .completed:
            return "Protected push completed"
        case .error:
            return "Structured command error"
        }
    }

    var lastUpdatedLine: String {
        "Updated \(lastUpdated.formatted(date: .omitted, time: .standard))"
    }

    var pushScopeDescription: String {
        guard let preview = pushPreview else { return "Unavailable" }
        switch preview.status {
        case .ready:
            return "\(preview.report?.discoveredFiles ?? 0) discovered, \(preview.report?.scannedFiles ?? 0) scanned, \(preview.report?.ignoredFiles ?? 0) ignored"
        case .upToDate:
            return "No candidate scope"
        case .noCommits:
            return "No commits available to inspect"
        case .completed:
            return "Push completed after evaluation"
        case .error:
            return "Failed to produce scope"
        }
    }

    var branchLine: String {
        guard let preview = pushPreview else { return "Unavailable" }
        let branch = preview.branch ?? "No branch"
        let upstream = preview.upstream ?? "No upstream"
        return "\(branch) → \(upstream)"
    }

    var pushExecutionDetail: String {
        guard let preview = pushPreview else { return "Unavailable" }
        return preview.outcomeDetail
    }

    var scanDetailLine: String? {
        guard let preview = pushPreview else { return nil }
        if preview.receipts.issueCount > 0 || preview.receipts.overridesApplied > 0 {
            return "\(preview.receipts.overridesApplied) overrides applied, \(preview.receipts.issueCount) receipt issues."
        }
        return nil
    }

    var priorityChecks: [DoctorCheck] {
        guard let doctorReport else { return [] }
        let important = doctorReport.checks.filter { $0.status == .fail || $0.status == .warn }
        return important.isEmpty ? Array(doctorReport.checks.prefix(4)) : important
    }

    func setRepository(_ url: URL) {
        repositoryURL = url
        errorMessage = nil
    }

    func refresh() async {
        guard let repositoryURL else { return }
        isRefreshing = true
        defer { isRefreshing = false }

        do {
            let console = try await WolfenceInspector.inspect(at: repositoryURL)
            doctorReport = console.doctorReport
            pushPreview = console.pushPreview
            repoConfiguration = console.repoConfiguration
            receiptPolicy = console.receiptPolicy
            auditEntries = console.auditEntries
            errorMessage = nil
            lastUpdated = Date()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    static var preview: WolfenceMonitor {
        let monitor = WolfenceMonitor()
        monitor.repositoryURL = URL(fileURLWithPath: "/Users/yoavperetz/Developer/Wolfence")
        monitor.repoConfiguration = RepoConfiguration(policyMode: "standard", ignorePaths: ["docs/"])
        monitor.receiptPolicy = ReceiptPolicy(
            requireExplicitCategory: false,
            requireSignedReceipts: false,
            requireReviewerMetadata: false,
            allowedReviewers: [],
            allowedApprovers: [],
            allowedKeyIDs: []
        )
        monitor.doctorReport = DoctorReport(
            repoRoot: "/Users/yoavperetz/Developer/Wolfence",
            effectiveMode: "standard",
            modeSource: "repo-file",
            summary: DoctorSummary(pass: 13, warn: 2, fail: 0, info: 4),
            checks: [
                DoctorCheck(name: "push remote", status: .warn, detail: "No Git remote is configured, so an initial protected push will fail after policy evaluation allows it.", remediation: "Add a remote before attempting a real push."),
                DoctorCheck(name: "pre-push", status: .warn, detail: "The managed pre-push hook is missing, so native git push is currently unguarded.", remediation: "Run `wolf init` to install the managed hook."),
                DoctorCheck(name: "audit log", status: .pass, detail: "The audit chain contains verified local evidence entries.", remediation: nil)
            ],
            result: "ok"
        )
        monitor.pushPreview = PushPreviewReport(
            command: "scan",
            scope: "push",
            action: "push-preview",
            repoRoot: "/Users/yoavperetz/Developer/Wolfence",
            mode: "standard",
            modeSource: "repo-file",
            status: .ready,
            branch: "main",
            upstream: nil,
            commitsAhead: 1,
            scannersRun: 5,
            report: ScanReport(
                findings: [],
                discoveredFiles: 10,
                scannedFiles: 10,
                ignoredFiles: 0,
                scannersRun: 5
            ),
            decision: PolicyDecision(verdict: .allow, blockingFindings: [], warningFindings: [], overriddenFindings: []),
            receipts: ReceiptSummary(issues: [], issueCount: 0, overridesApplied: 0),
            scanScope: ScanScope(
                discoveredFiles: 10,
                scannedFiles: 10,
                ignoredFiles: 0,
                scannedPaths: [
                    "Wolfence/ContentView.swift",
                    "Wolfence/WolfenceApp.swift",
                    "WolfenceTests/WolfenceTests.swift"
                ],
                ignoredPaths: [],
                ignorePatterns: ["docs/"]
            ),
            result: "completed",
            error: nil
        )
        monitor.auditEntries = [
            AuditEntry(
                version: 3,
                sequence: 26,
                timestampUnix: 1_775_769_634,
                source: "push-command",
                action: "push",
                status: "completed",
                outcome: "push-completed",
                detail: nil,
                verdict: "allow",
                discoveredFiles: 24,
                candidateFiles: 15,
                ignoredFiles: 9,
                findings: 0,
                warnings: 0,
                blocks: 0,
                overridesApplied: 0,
                receiptIssues: 0,
                branch: "main",
                upstream: "origin/main",
                commitsAhead: 1
            ),
            AuditEntry(
                version: 3,
                sequence: 24,
                timestampUnix: 1_775_769_632,
                source: "push-command",
                action: "push",
                status: "ready",
                outcome: "policy-allowed",
                detail: nil,
                verdict: "allow",
                discoveredFiles: 24,
                candidateFiles: 15,
                ignoredFiles: 9,
                findings: 0,
                warnings: 0,
                blocks: 0,
                overridesApplied: 0,
                receiptIssues: 0,
                branch: "main",
                upstream: "origin/main",
                commitsAhead: 1
            )
        ]
        return monitor
    }

    static var previewSecondary: WolfenceMonitor {
        let monitor = WolfenceMonitor.preview
        monitor.repositoryURL = URL(fileURLWithPath: "/Users/yoavperetz/Developer/Dragon")
        monitor.lastUpdated = Date().addingTimeInterval(-420)
        monitor.repoConfiguration = RepoConfiguration(policyMode: "strict", ignorePaths: ["docs/", "Fixtures/"])
        monitor.doctorReport = DoctorReport(
            repoRoot: "/Users/yoavperetz/Developer/Dragon",
            effectiveMode: "strict",
            modeSource: "repo-file",
            summary: DoctorSummary(pass: 9, warn: 1, fail: 0, info: 3),
            checks: [
                DoctorCheck(name: "managed hook", status: .pass, detail: "Managed pre-push hook is installed.", remediation: nil),
                DoctorCheck(name: "receipt approval policy", status: .warn, detail: "Signed receipts are not required for configuration overrides.", remediation: "Require signatures for production-facing exception categories.")
            ],
            result: "ok"
        )
        monitor.pushPreview = PushPreviewReport(
            command: "scan",
            scope: "push",
            action: "push-preview",
            repoRoot: "/Users/yoavperetz/Developer/Dragon",
            mode: "strict",
            modeSource: "repo-file",
            status: .ready,
            branch: "release/hardening",
            upstream: "origin/release/hardening",
            commitsAhead: 3,
            scannersRun: 5,
            report: ScanReport(
                findings: [],
                discoveredFiles: 42,
                scannedFiles: 31,
                ignoredFiles: 11,
                scannersRun: 5
            ),
            decision: PolicyDecision(
                verdict: .warn,
                blockingFindings: [],
                warningFindings: [
                    PolicyFinding(
                        finding: Finding(
                            scanner: "policy",
                            severity: "medium",
                            confidence: "high",
                            category: "configuration",
                            file: "deploy.yml",
                            line: 18,
                            title: "Deployment secrets exposed to broad environment scope",
                            detail: "A deploy workflow exposes secret material to multiple jobs.",
                            remediation: "Restrict secret scope to the deployment job only.",
                            fingerprint: "dragon-config-001"
                        ),
                        rationale: "Strict mode surfaces the finding as an operator warning."
                    )
                ],
                overriddenFindings: []
            ),
            receipts: ReceiptSummary(issues: [], issueCount: 0, overridesApplied: 0),
            scanScope: ScanScope(
                discoveredFiles: 42,
                scannedFiles: 31,
                ignoredFiles: 11,
                scannedPaths: ["Sources/App/SecurityGate.swift", "deploy.yml", "Package.swift"],
                ignoredPaths: ["docs/architecture.md"],
                ignorePatterns: ["docs/"]
            ),
            result: "completed",
            error: nil
        )
        monitor.auditEntries = [
            AuditEntry(
                version: 3,
                sequence: 114,
                timestampUnix: 1_775_770_540,
                source: "push-command",
                action: "push",
                status: "ready",
                outcome: "policy-allowed",
                detail: "Transport has not been attempted yet.",
                verdict: "warn",
                discoveredFiles: 42,
                candidateFiles: 31,
                ignoredFiles: 11,
                findings: 1,
                warnings: 1,
                blocks: 0,
                overridesApplied: 0,
                receiptIssues: 0,
                branch: "release/hardening",
                upstream: "origin/release/hardening",
                commitsAhead: 3
            )
        ]
        return monitor
    }
}

private enum WolfenceInspector {
    nonisolated static func inspect(at repositoryURL: URL) async throws -> ConsoleState {
        try await Task.detached(priority: .userInitiated) {
            let repoRoot = repositoryURL
            let doctor = try await loadDoctor(at: repoRoot)
            let pushPreview = try await loadPushPreview(at: repoRoot)
            let config = try loadRepoConfiguration(at: repoRoot)
            let receiptPolicy = try loadReceiptPolicy(at: repoRoot)
            let auditEntries = try await loadAuditEntries(at: repoRoot)

            return ConsoleState(
                doctorReport: doctor,
                pushPreview: pushPreview,
                repoConfiguration: config,
                receiptPolicy: receiptPolicy,
                auditEntries: auditEntries
            )
        }.value
    }

    private nonisolated static func loadDoctor(at repoRoot: URL) async throws -> DoctorReport? {
        guard let output = try runWolfJSON(arguments: ["doctor", "--json"], in: repoRoot) else {
            return nil
        }
        return try await MainActor.run {
            try JSONDecoder().decode(DoctorReport.self, from: output)
        }
    }

    private nonisolated static func loadPushPreview(at repoRoot: URL) async throws -> PushPreviewReport? {
        guard let output = try runWolfJSON(arguments: ["scan", "push", "--json"], in: repoRoot) else {
            return nil
        }
        return try await MainActor.run {
            try JSONDecoder().decode(PushPreviewReport.self, from: output)
        }
    }

    private nonisolated static func loadRepoConfiguration(at repoRoot: URL) throws -> RepoConfiguration {
        let fileURL = repoRoot.appending(path: ".wolfence/config.toml")
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return RepoConfiguration()
        }

        let text = try String(contentsOf: fileURL, encoding: .utf8)
        return RepoConfiguration(
            policyMode: matchValue(in: text, key: "mode"),
            ignorePaths: matchArray(in: text, key: "ignore_paths")
        )
    }

    private nonisolated static func loadReceiptPolicy(at repoRoot: URL) throws -> ReceiptPolicy {
        let fileURL = repoRoot.appending(path: ".wolfence/policy/receipts.toml")
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return ReceiptPolicy()
        }

        let text = try String(contentsOf: fileURL, encoding: .utf8)
        return ReceiptPolicy(
            requireExplicitCategory: matchBoolean(in: text, key: "require_explicit_category") ?? false,
            requireSignedReceipts: matchBoolean(in: text, key: "require_signed_receipts") ?? false,
            requireReviewerMetadata: matchBoolean(in: text, key: "require_reviewer_metadata") ?? false,
            allowedReviewers: matchArray(in: text, key: "allowed_reviewers"),
            allowedApprovers: matchArray(in: text, key: "allowed_approvers"),
            allowedKeyIDs: matchArray(in: text, key: "allowed_key_ids")
        )
    }

    private nonisolated static func loadAuditEntries(at repoRoot: URL) async throws -> [AuditEntry] {
        let fileURL = repoRoot.appending(path: ".wolfence/audit/decisions.jsonl")
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return []
        }

        let text = try String(contentsOf: fileURL, encoding: .utf8)
        let lines = text
            .split(whereSeparator: \.isNewline)
            .map(String.init)

        return await MainActor.run {
            let decoder = JSONDecoder()
            return lines
                .compactMap { line in
                    guard let data = line.data(using: .utf8) else { return nil }
                    return try? decoder.decode(AuditEntry.self, from: data)
                }
                .sorted { $0.sequence > $1.sequence }
        }
    }

    private nonisolated static func runWolfJSON(arguments: [String], in repoRoot: URL) throws -> Data? {
        if let binary = discoverWolfBinary(in: repoRoot) {
            let output = try shell(binary.path, arguments, in: repoRoot, allowFailure: true, useEnv: false)
            guard !output.stdout.isEmpty else { return nil }
            return output.stdout.data(using: .utf8)
        }

        let output = try shell("wolf", arguments, in: repoRoot, allowFailure: true)
        if !output.stdout.isEmpty {
            return output.stdout.data(using: .utf8)
        }

        return nil
    }

    private nonisolated static func discoverWolfBinary(in repoRoot: URL) -> URL? {
        let candidates = [
            repoRoot.appending(path: "target/debug/wolf"),
            repoRoot.appending(path: "target/release/wolf")
        ]

        return candidates.first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }

    private nonisolated static func shell(_ command: String, _ arguments: [String], in directory: URL, allowFailure: Bool = false, useEnv: Bool = true) throws -> ShellOutput {
        let process = Process()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()

        if useEnv {
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = [command] + arguments
        } else {
            process.executableURL = URL(fileURLWithPath: command)
            process.arguments = arguments
        }

        process.currentDirectoryURL = directory
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
        } catch {
            if allowFailure {
                return ShellOutput(status: 127, stdout: "", stderr: error.localizedDescription)
            }
            throw error
        }

        process.waitUntilExit()

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        let stdout = String(data: stdoutData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let stderr = String(data: stderrData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        let output = ShellOutput(status: process.terminationStatus, stdout: stdout, stderr: stderr)
        if !allowFailure, output.status != 0 {
            throw WolfenceError.commandFailed(output.combinedOutput.nilIfEmpty ?? "The command failed without output.")
        }
        return output
    }

    private nonisolated static func matchValue(in text: String, key: String) -> String? {
        guard let line = text.split(whereSeparator: \.isNewline).first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("\(key) =") }) else {
            return nil
        }
        let value = line.split(separator: "=", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces) ?? ""
        return value.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
    }

    private nonisolated static func matchBoolean(in text: String, key: String) -> Bool? {
        guard let value = matchValue(in: text, key: key) else { return nil }
        switch value {
        case "true":
            return true
        case "false":
            return false
        default:
            return nil
        }
    }

    private nonisolated static func matchArray(in text: String, key: String) -> [String] {
        guard let line = text.split(whereSeparator: \.isNewline).first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("\(key) =") }) else {
            return []
        }

        let rawValue = line.split(separator: "=", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces) ?? ""
        guard rawValue.first == "[", rawValue.last == "]" else { return [] }

        return rawValue
            .dropFirst()
            .dropLast()
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"")) }
            .filter { !$0.isEmpty }
    }
}

private struct ConsoleState: Sendable {
    let doctorReport: DoctorReport?
    let pushPreview: PushPreviewReport?
    let repoConfiguration: RepoConfiguration
    let receiptPolicy: ReceiptPolicy
    let auditEntries: [AuditEntry]
}

private struct RepoConfiguration: Sendable {
    var policyMode: String?
    var ignorePaths: [String]

    nonisolated init(policyMode: String? = nil, ignorePaths: [String] = []) {
        self.policyMode = policyMode
        self.ignorePaths = ignorePaths
    }
}

private struct ReceiptPolicy: Sendable {
    var requireExplicitCategory: Bool
    var requireSignedReceipts: Bool
    var requireReviewerMetadata: Bool
    var allowedReviewers: [String]
    var allowedApprovers: [String]
    var allowedKeyIDs: [String]

    nonisolated init(
        requireExplicitCategory: Bool = false,
        requireSignedReceipts: Bool = false,
        requireReviewerMetadata: Bool = false,
        allowedReviewers: [String] = [],
        allowedApprovers: [String] = [],
        allowedKeyIDs: [String] = []
    ) {
        self.requireExplicitCategory = requireExplicitCategory
        self.requireSignedReceipts = requireSignedReceipts
        self.requireReviewerMetadata = requireReviewerMetadata
        self.allowedReviewers = allowedReviewers
        self.allowedApprovers = allowedApprovers
        self.allowedKeyIDs = allowedKeyIDs
    }
}

private struct DoctorReport: Decodable, Sendable {
    let repoRoot: String
    let effectiveMode: String
    let modeSource: String
    let summary: DoctorSummary
    let checks: [DoctorCheck]
    let result: String

    enum CodingKeys: String, CodingKey {
        case repoRoot = "repo_root"
        case effectiveMode = "effective_mode"
        case modeSource = "mode_source"
        case summary, checks, result
    }
}

private struct DoctorSummary: Decodable, Sendable {
    let pass: Int
    let warn: Int
    let fail: Int
    let info: Int
}

private struct DoctorCheck: Decodable, Identifiable, Sendable {
    var id: String { name }
    let name: String
    let status: DoctorStatus
    let detail: String
    let remediation: String?
}

private enum DoctorStatus: String, Decodable, Sendable {
    case pass
    case warn
    case fail
    case info
}

private struct PushPreviewReport: Decodable, Sendable {
    let command: String
    let scope: String
    let action: String
    let repoRoot: String
    let mode: String?
    let modeSource: String?
    let status: PreviewStatus
    let branch: String?
    let upstream: String?
    let commitsAhead: Int?
    let scannersRun: Int?
    let report: ScanReport?
    let decision: PolicyDecision?
    let receipts: ReceiptSummary
    let scanScope: ScanScope?
    let result: String
    let error: CommandError?

    enum CodingKeys: String, CodingKey {
        case command, scope, action, mode, status, branch, upstream, result, error, receipts, decision, report
        case repoRoot = "repo_root"
        case modeSource = "mode_source"
        case commitsAhead = "commits_ahead"
        case scannersRun = "scanners_run"
        case scanScope = "scan_scope"
    }

    var outcomeDetail: String {
        switch status {
        case .ready:
            return "Policy \(decision?.verdict.displayName.lowercased() ?? "evaluation") for \(commitsAhead ?? 0) outgoing commit."
        case .upToDate:
            return "No pending outbound commits were found."
        case .noCommits:
            return "No commits are available to send."
        case .completed:
            return "The protected push path completed."
        case .error:
            return error?.message ?? "Wolfence returned an error envelope."
        }
    }
}

private enum PreviewStatus: String, Decodable, Sendable {
    case noCommits = "no-commits"
    case upToDate = "up-to-date"
    case ready
    case completed
    case error
}

private struct ScanReport: Decodable, Sendable {
    let findings: [Finding]
    let discoveredFiles: Int
    let scannedFiles: Int
    let ignoredFiles: Int
    let scannersRun: Int

    enum CodingKeys: String, CodingKey {
        case findings
        case discoveredFiles = "discovered_files"
        case scannedFiles = "scanned_files"
        case ignoredFiles = "ignored_files"
        case scannersRun = "scanners_run"
    }
}

private struct PolicyDecision: Decodable, Sendable {
    let verdict: Verdict
    let blockingFindings: [PolicyFinding]
    let warningFindings: [PolicyFinding]
    let overriddenFindings: [OverriddenFinding]

    enum CodingKeys: String, CodingKey {
        case verdict
        case blockingFindings = "blocking_findings"
        case warningFindings = "warning_findings"
        case overriddenFindings = "overridden_findings"
    }
}

private enum Verdict: String, Decodable, Sendable {
    case allow
    case warn
    case block

    var displayName: String {
        switch self {
        case .allow:
            return "Allow"
        case .warn:
            return "Warn"
        case .block:
            return "Block"
        }
    }
}

private struct PolicyFinding: Decodable, Identifiable, Sendable {
    var id: String { finding.fingerprint + rationale }
    let finding: Finding
    let rationale: String
}

private struct OverriddenFinding: Decodable, Identifiable, Sendable {
    var id: String { finding.fingerprint + receipt.receiptID }
    let finding: Finding
    let receipt: OverrideReceipt
}

private struct OverrideReceipt: Decodable, Sendable {
    let receiptID: String

    enum CodingKeys: String, CodingKey {
        case receiptID = "receipt_id"
    }
}

private struct Finding: Decodable, Sendable {
    let scanner: String
    let severity: String
    let confidence: String
    let category: String
    let file: String?
    let line: Int?
    let title: String
    let detail: String
    let remediation: String
    let fingerprint: String
}

private struct ReceiptSummary: Decodable, Sendable {
    let issues: [String]
    let issueCount: Int
    let overridesApplied: Int

    enum CodingKeys: String, CodingKey {
        case issues
        case issueCount = "issue_count"
        case overridesApplied = "overrides_applied"
    }
}

private struct ScanScope: Decodable, Sendable {
    let discoveredFiles: Int
    let scannedFiles: Int
    let ignoredFiles: Int
    let scannedPaths: [String]
    let ignoredPaths: [String]
    let ignorePatterns: [String]

    enum CodingKeys: String, CodingKey {
        case discoveredFiles = "discovered_files"
        case scannedFiles = "scanned_files"
        case ignoredFiles = "ignored_files"
        case scannedPaths = "scanned_paths"
        case ignoredPaths = "ignored_paths"
        case ignorePatterns = "ignore_patterns"
    }
}

private struct AuditEntry: Decodable, Identifiable, Sendable {
    var id: Int { sequence }

    let version: Int?
    let sequence: Int
    let timestampUnix: UInt64
    let source: String
    let action: String
    let status: String
    let outcome: String
    let detail: String?
    let verdict: String?
    let discoveredFiles: Int?
    let candidateFiles: Int
    let ignoredFiles: Int?
    let findings: Int
    let warnings: Int
    let blocks: Int
    let overridesApplied: Int
    let receiptIssues: Int
    let branch: String?
    let upstream: String?
    let commitsAhead: Int?

    enum CodingKeys: String, CodingKey {
        case version, sequence, source, action, status, outcome, detail, verdict, findings, warnings, blocks, branch, upstream
        case timestampUnix = "timestamp_unix"
        case discoveredFiles = "discovered_files"
        case candidateFiles = "candidate_files"
        case ignoredFiles = "ignored_files"
        case overridesApplied = "overrides_applied"
        case receiptIssues = "receipt_issues"
        case commitsAhead = "commits_ahead"
    }

    var timestampLabel: String {
        Date(timeIntervalSince1970: TimeInterval(timestampUnix))
            .formatted(date: .abbreviated, time: .shortened)
    }

    var tone: Color {
        switch verdict {
        case "block":
            return WolfenceTheme.alert
        case "warn":
            return WolfenceTheme.caution
        case "allow":
            return WolfenceTheme.ok
        default:
            return WolfenceTheme.steel
        }
    }

    var outcomeSummary: String {
        outcome.replacingOccurrences(of: "-", with: " ").capitalized
    }

    var contextLine: String {
        let branchPart = branch ?? "no branch"
        let upstreamPart = upstream ?? "no upstream"
        let aheadPart = commitsAhead.map { "\($0) ahead" } ?? "no ahead count"
        return "\(branchPart) • \(upstreamPart) • \(aheadPart)"
    }

    var countsLine: String {
        let discovered = discoveredFiles ?? candidateFiles
        let ignored = ignoredFiles ?? 0
        return "\(discovered) files • \(findings) findings • \(ignored) ignored"
    }
}

private struct CommandError: Decodable, Sendable {
    let kind: String
    let message: String
}

private struct ShellOutput: Sendable {
    let status: Int32
    let stdout: String
    let stderr: String

    nonisolated var combinedOutput: String {
        [stdout, stderr]
            .filter { !$0.isEmpty }
            .joined(separator: "\n")
    }
}

private enum WolfenceError: LocalizedError {
    case commandFailed(String)

    var errorDescription: String? {
        switch self {
        case .commandFailed(let message):
            return message
        }
    }
}

private enum WolfenceTheme {
    static let parchment = Color(red: 0.955, green: 0.956, blue: 0.905)
    static let ivory = Color(red: 0.982, green: 0.981, blue: 0.955)
    static let surface = Color.white.opacity(0.74)
    static let panel = Color.white.opacity(0.62)
    static let primaryInk = Color(red: 0.09, green: 0.15, blue: 0.27)
    static let secondaryInk = Color(red: 0.23, green: 0.28, blue: 0.35)
    static let mutedInk = Color(red: 0.42, green: 0.45, blue: 0.48)
    static let navy = Color(red: 0.13, green: 0.21, blue: 0.35)
    static let steel = Color(red: 0.35, green: 0.39, blue: 0.46)
    static let action = Color(red: 0.14, green: 0.26, blue: 0.44)
    static let ok = Color(red: 0.18, green: 0.43, blue: 0.31)
    static let caution = Color(red: 0.63, green: 0.46, blue: 0.15)
    static let alert = Color(red: 0.66, green: 0.25, blue: 0.22)
    static let rule = Color(red: 0.09, green: 0.15, blue: 0.27).opacity(0.12)
    static let sidebarGlass = Color.white.opacity(0.22)

    static let windowBackground = LinearGradient(
        colors: [
            ivory,
            parchment,
            Color(red: 0.93, green: 0.94, blue: 0.89)
        ],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
}

private struct SurfacePanel<Content: View>: View {
    let title: String?
    let subtitle: String?
    @ViewBuilder let content: Content

    init(title: String? = nil, subtitle: String? = nil, @ViewBuilder content: () -> Content) {
        self.title = title
        self.subtitle = subtitle
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let title {
                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .font(.system(size: 22, weight: .regular, design: .serif))
                        .foregroundStyle(WolfenceTheme.primaryInk)
                    if let subtitle {
                        Text(subtitle)
                            .font(.system(size: 12, weight: .semibold, design: .rounded))
                            .foregroundStyle(WolfenceTheme.mutedInk)
                            .textCase(.uppercase)
                    }
                }
            }

            content
        }
        .padding(22)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 28, style: .continuous)
                .fill(WolfenceTheme.panel)
                .overlay(
                    RoundedRectangle(cornerRadius: 28, style: .continuous)
                        .stroke(WolfenceTheme.rule, lineWidth: 1)
                )
                .shadow(color: WolfenceTheme.navy.opacity(0.06), radius: 18, y: 12)
        )
    }
}

private struct MetricPanel: View {
    let title: String
    let value: String
    let detail: String
    let tone: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title.uppercased())
                .font(.system(size: 11, weight: .bold, design: .rounded))
                .foregroundStyle(WolfenceTheme.mutedInk)

            Text(value)
                .font(.system(size: 28, weight: .semibold, design: .serif))
                .foregroundStyle(tone)

            Text(detail)
                .font(.system(size: 12, weight: .medium, design: .rounded))
                .foregroundStyle(WolfenceTheme.secondaryInk)
                .lineLimit(2)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .fill(Color.white.opacity(0.52))
                .overlay(
                    RoundedRectangle(cornerRadius: 24, style: .continuous)
                        .stroke(WolfenceTheme.rule, lineWidth: 1)
                )
        )
    }
}

private struct InfoRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top, spacing: 18) {
            Text(label.uppercased())
                .font(.system(size: 11, weight: .bold, design: .rounded))
                .foregroundStyle(WolfenceTheme.mutedInk)
                .frame(width: 124, alignment: .leading)

            Text(value)
                .font(.system(size: 13, weight: .medium, design: .rounded))
                .foregroundStyle(WolfenceTheme.primaryInk)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private extension String {
    nonisolated var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}

#Preview {
    ContentView(previewWorkspace: .preview)
}

#Preview("Loaded Console") {
    ContentView(previewWorkspace: .preview)
}
