import AppKit
import Observation
import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @AppStorage("workspaceRepositoryPaths") private var workspaceRepositoryPaths = "[]"
    @AppStorage("selectedRepositoryPath") private var selectedRepositoryPath = ""
    @AppStorage("workspaceRepositoryIcons") private var workspaceRepositoryIcons = "{}"
    @AppStorage("sidebarCollapsed") private var sidebarCollapsed = false
    @State private var workspace = WorkspaceStore()
    @State private var iconEditorRepositoryID: String?
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

    private var sidebarSectionPadding: CGFloat {
        sidebarCollapsed ? 0 : 12
    }

    private var sidebarToggleCollapsedLeadingOffset: CGFloat {
        18
    }

    private var sidebarToggleExpandedTrailingOffset: CGFloat {
        44
    }

    private var sidebarToggleLeadingInset: CGFloat {
        sidebarCollapsed
            ? sidebarWidth + sidebarToggleCollapsedLeadingOffset
            : sidebarWidth - sidebarToggleExpandedTrailingOffset
    }

    private var sidebarToggleTopInset: CGFloat {
        -20
    }

    private var collapsedHeaderLeadingInset: CGFloat {
        40
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
        .sheet(
            isPresented: Binding(
                get: { iconEditorRepositoryID != nil },
                set: { if !$0 { iconEditorRepositoryID = nil } }
            )
        ) {
            if let repositoryID = iconEditorRepositoryID,
               let repository = workspace.repositories.first(where: { $0.id == repositoryID }) {
                RepositoryIconEditorSheet(
                    repository: repository,
                    onSave: { customization in
                        workspace.updateRepositoryIcon(id: repositoryID, customization: customization)
                        persistWorkspace()
                        iconEditorRepositoryID = nil
                    },
                    onCancel: {
                        iconEditorRepositoryID = nil
                    }
                )
            }
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
                .buttonStyle(WolfenceActionButtonStyle(tone: WolfenceTheme.action, prominence: .primary))

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
                .animation(.snappy(duration: 0.18, extraBounce: 0), value: sidebarCollapsed)

            VStack(spacing: 0) {
                windowChrome
                detailArea
                    .transaction { transaction in
                        transaction.animation = nil
                    }
            }
        }
        .background(WolfenceTheme.surface.opacity(0.45))
        .clipShape(RoundedRectangle(cornerRadius: 0))
        .ignoresSafeArea(edges: .top)
        .overlay(alignment: .topLeading) {
            sidebarToggleButton
                .offset(x: sidebarToggleLeadingInset, y: sidebarToggleTopInset)
                .animation(.snappy(duration: 0.18, extraBounce: 0), value: sidebarCollapsed)
        }
    }

    private var windowChrome: some View {
        HStack(spacing: 18) {
            if sidebarCollapsed {
                VStack(alignment: .leading, spacing: 2) {
                    Text(activeRepository?.displayTitle ?? "Workspace")
                        .font(.system(size: 24, weight: .regular, design: .serif))
                        .foregroundStyle(WolfenceTheme.primaryInk)
                }
                .padding(.leading, collapsedHeaderLeadingInset)
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
                .buttonStyle(WolfenceIconButtonStyle(tone: WolfenceTheme.action))
                .disabled(activeMonitor == nil || (activeMonitor?.isRefreshing ?? false))

                Button {
                    Task { await workspace.refreshAllRepositories() }
                } label: {
                    Image(systemName: "arrow.triangle.2.circlepath")
                }
                .buttonStyle(WolfenceIconButtonStyle(tone: WolfenceTheme.navy))
                .disabled(workspace.repositories.isEmpty)
            }
        }
        .padding(.leading, 18)
        .padding(.trailing, 26)
        .padding(.top, 10)
        .padding(.bottom, 8)
    }

    private var sidebar: some View {
        VStack(alignment: sidebarCollapsed ? .center : .leading, spacing: 0) {
            if !sidebarCollapsed {
                HStack(spacing: 10) {
                    Color.clear
                        .frame(width: 54, height: 14)

                    Spacer(minLength: 0)

                    Color.clear
                        .frame(width: 32, height: 32)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.top, 10)
                .padding(.bottom, -5)
                .padding(.horizontal, 12)
            }

            HStack(spacing: 14) {
                wolfHeaderMark(size: 60)

                if !sidebarCollapsed {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Wolfence")
                            .font(.system(size: 24, weight: .semibold, design: .serif))
                            .foregroundStyle(WolfenceTheme.primaryInk)
                        Text("Repository Gate")
                            .font(.system(size: 12, weight: .semibold, design: .rounded))
                            .foregroundStyle(WolfenceTheme.mutedInk)
                    }
                }

                if !sidebarCollapsed {
                    Spacer(minLength: 0)
                }
            }
            .frame(maxWidth: .infinity, alignment: sidebarCollapsed ? .center : .leading)
            .padding(.horizontal, sidebarSectionPadding)
            .padding(.top, sidebarCollapsed ? 30 : 0)
            .padding(.bottom, sidebarCollapsed ? 12 : 10)

            if !sidebarCollapsed {
                Text("\(workspace.repositories.count) workspaces")
                    .font(.system(size: 10, weight: .bold, design: .rounded))
                    .foregroundStyle(WolfenceTheme.mutedInk)
                    .textCase(.uppercase)
                    .padding(.top, 16)
                    .padding(.bottom, 8)
                    .padding(.horizontal, sidebarSectionPadding)
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
                            onCustomizeIcon: {
                                iconEditorRepositoryID = repository.id
                            },
                            onRemove: {
                                workspace.removeRepository(id: repository.id)
                                persistWorkspace()
                            }
                        )
                    }
                }
                .frame(maxWidth: .infinity, alignment: sidebarCollapsed ? .center : .leading)
                .padding(.horizontal, sidebarSectionPadding)
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
            .padding(.horizontal, sidebarSectionPadding)
            .padding(.bottom, sidebarCollapsed ? 0 : 10)
        }
        .padding(.horizontal, sidebarCollapsed ? 10 : 0)
        .padding(.bottom, 10)
        .frame(width: sidebarWidth)
        .frame(maxHeight: .infinity)
        .animation(.snappy(duration: 0.18, extraBounce: 0), value: sidebarCollapsed)
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

    private var sidebarToggleButton: some View {
        Button {
            withAnimation(.snappy(duration: 0.18, extraBounce: 0)) {
                sidebarCollapsed.toggle()
            }
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
    }

    private var detailArea: some View {
        Group {
            if let repository = activeRepository, let monitor = activeMonitor {
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        repoHeroPanel(repository: repository, monitor: monitor)
                        statusGrid(monitor: monitor)
                        detailGrid(monitor: monitor)
                        auditPanel(monitor: monitor)
                    }
                    .padding(.horizontal, 24)
                    .padding(.top, 10)
                    .padding(.bottom, 18)
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
        SurfacePanel(emphasis: .hero) {
            HStack(alignment: .top, spacing: 24) {
                VStack(alignment: .leading, spacing: 14) {
                    VStack(alignment: .leading, spacing: 7) {
                        Text(monitor.pushSafetyHeadline)
                            .font(.system(size: 42, weight: .semibold, design: .serif))
                            .foregroundStyle(monitor.heroColor)

                        Text(monitor.pushSafetySummary)
                            .font(.system(size: 15, weight: .medium, design: .rounded))
                            .foregroundStyle(WolfenceTheme.secondaryInk)

                        Text(repository.path)
                            .font(.system(size: 12, weight: .medium, design: .monospaced))
                            .foregroundStyle(WolfenceTheme.mutedInk)
                            .textSelection(.enabled)
                    }

                    HStack(spacing: 12) {
                        Button {
                            Task { await repository.monitor.scan() }
                        } label: {
                            Label(repository.monitor.isRefreshing ? "Scanning…" : "Scan", systemImage: "magnifyingglass")
                        }
                        .buttonStyle(WolfenceActionButtonStyle(tone: WolfenceTheme.action, prominence: .primary))

                        Button("Reveal in Finder") {
                            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: repository.path)])
                        }
                        .buttonStyle(WolfenceActionButtonStyle(tone: WolfenceTheme.navy))

                        Button("Copy Path") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(repository.path, forType: .string)
                        }
                        .buttonStyle(WolfenceActionButtonStyle(tone: WolfenceTheme.steel))
                    }
                }

                Spacer(minLength: 24)

                VStack(alignment: .trailing, spacing: 12) {
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
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 420), spacing: 22)], spacing: 18) {
            pushPanel(monitor: monitor)
            doctorPanel(monitor: monitor)
            governancePanel(monitor: monitor)
            policyPanel(monitor: monitor)
            findingsPanel(monitor: monitor)
            scanScopePanel(monitor: monitor)
            receiptsPanel(monitor: monitor)
        }
    }

    private func pushPanel(monitor: WolfenceMonitor) -> some View {
        SurfacePanel(title: "Push Posture", subtitle: "Primary decision surface") {
            VStack(alignment: .leading, spacing: 12) {
                InfoRow(label: "Verdict", value: monitor.pushDecisionValue)
                InfoRow(label: "Scope", value: monitor.pushScopeDescription)
                InfoRow(label: "Branch", value: monitor.branchLine)
                InfoRow(label: "Execution", value: monitor.pushExecutionDetail)

                if let detail = monitor.scanDetailLine {
                    Text(detail)
                        .font(.system(size: 13, weight: .medium, design: .rounded))
                        .foregroundStyle(WolfenceTheme.secondaryInk)
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Scan Log")
                        .font(.system(size: 12, weight: .bold, design: .rounded))
                        .foregroundStyle(WolfenceTheme.mutedInk)

                    ScrollView {
                        Text(monitor.lastScanLog)
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundStyle(WolfenceTheme.secondaryInk)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                    }
                    .frame(minHeight: 88, maxHeight: 132)
                    .padding(10)
                    .background(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(Color.white.opacity(0.34))
                            .overlay(
                                RoundedRectangle(cornerRadius: 12, style: .continuous)
                                    .stroke(WolfenceTheme.rule, lineWidth: 1)
                            )
                    )
                }
            }
        }
    }

    private func doctorPanel(monitor: WolfenceMonitor) -> some View {
        SurfacePanel(title: "Local Trust", subtitle: "Doctor summary and weak points") {
            VStack(alignment: .leading, spacing: 12) {
                if let doctor = monitor.doctorReport {
                    Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 10) {
                        GridRow {
                            summaryValue("Pass", value: doctor.summary.pass, tone: WolfenceTheme.ok)
                            summaryValue("Warn", value: doctor.summary.warn, tone: WolfenceTheme.caution)
                            summaryValue("Fail", value: doctor.summary.fail, tone: WolfenceTheme.alert)
                            summaryValue("Info", value: doctor.summary.info, tone: WolfenceTheme.steel)
                        }
                    }

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
            VStack(alignment: .leading, spacing: 12) {
                InfoRow(label: "Mode", value: monitor.policyModeDisplay)
                InfoRow(label: "Source", value: monitor.modeSourceDisplay)
                InfoRow(label: "Ignored Paths", value: monitor.ignorePathsDisplay)
                InfoRow(label: "Receipt Signatures", value: monitor.signaturePolicyDisplay)
                InfoRow(label: "Reviewer Metadata", value: monitor.reviewerPolicyDisplay)
                InfoRow(label: "Allowed Approvers", value: monitor.approverDisplay)
            }
        }
    }

    private func governancePanel(monitor: WolfenceMonitor) -> some View {
        SurfacePanel(title: "GitHub Governance", subtitle: "Live repo drift and branch protection intent") {
            VStack(alignment: .leading, spacing: 12) {
                if let check = monitor.githubGovernanceCheck {
                    InfoRow(label: "Status", value: check.status.displayLabel)
                    Text(check.detail)
                        .font(.system(size: 12, weight: .medium, design: .rounded))
                        .foregroundStyle(WolfenceTheme.secondaryInk)

                    if let remediation = check.remediation {
                        Text(remediation)
                            .font(.system(size: 12, weight: .medium, design: .rounded))
                            .foregroundStyle(check.status.tone)
                    }
                } else {
                    unavailableState(
                        title: "No live governance signal",
                        detail: "Doctor did not return a live GitHub governance comparison for this repository."
                    )
                }
            }
        }
    }

    private func findingsPanel(monitor: WolfenceMonitor) -> some View {
        SurfacePanel(title: "Findings & Exceptions", subtitle: "Active push preview evidence") {
            VStack(alignment: .leading, spacing: 12) {
                if let scan = monitor.pushPreview {
                    InfoRow(label: "Findings", value: "\(scan.report?.findings.count ?? 0)")
                    InfoRow(label: "New Findings", value: "\(scan.report?.findingHistory?.newFindings ?? 0)")
                    InfoRow(label: "Recurring", value: "\(scan.report?.findingHistory?.recurringFindings ?? 0)")
                    InfoRow(label: "Accepted Baseline", value: "\(scan.report?.findingBaseline?.acceptedFindings ?? 0)")
                    InfoRow(label: "Needs Review", value: "\(scan.report?.findingBaseline?.unacceptedFindings ?? 0)")
                    InfoRow(label: "Blocking Findings", value: "\(scan.decision?.blockingFindings.count ?? 0)")
                    InfoRow(label: "Warning Findings", value: "\(scan.decision?.warningFindings.count ?? 0)")
                    InfoRow(label: "Overrides Applied", value: "\(scan.receipts.overridesApplied)")
                    InfoRow(label: "Receipt Issues", value: "\(scan.receipts.issueCount)")

                    if let topFinding = monitor.topFinding {
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(alignment: .center, spacing: 8) {
                                Text(topFinding.title)
                                    .font(.system(size: 14, weight: .semibold, design: .rounded))
                                    .foregroundStyle(WolfenceTheme.primaryInk)

                                if let history = topFinding.history {
                                    Text(history.statusLabel)
                                        .font(.system(size: 10, weight: .bold, design: .rounded))
                                        .foregroundStyle(history.tone)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 3)
                                        .background(history.tone.opacity(0.12), in: Capsule())
                                }

                                if let baseline = topFinding.baseline {
                                    Text(baseline.statusLabel)
                                        .font(.system(size: 10, weight: .bold, design: .rounded))
                                        .foregroundStyle(baseline.tone)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 3)
                                        .background(baseline.tone.opacity(0.12), in: Capsule())
                                }
                            }
                            Text(topFinding.detail)
                                .font(.system(size: 12, weight: .medium, design: .rounded))
                                .foregroundStyle(WolfenceTheme.secondaryInk)
                            Text(topFinding.remediationAdvice.primaryAction)
                                .font(.system(size: 12, weight: .semibold, design: .rounded))
                                .foregroundStyle(WolfenceTheme.caution)
                            Text("\(topFinding.remediationAdvice.urgencyLabel) • \(topFinding.remediationAdvice.ownerSurfaceLabel)")
                                .font(.system(size: 11, weight: .medium, design: .rounded))
                                .foregroundStyle(WolfenceTheme.mutedInk)
                            if let command = topFinding.remediationAdvice.primaryCommand {
                                Text(command)
                                    .font(.system(size: 11, weight: .medium, design: .monospaced))
                                    .foregroundStyle(WolfenceTheme.secondaryInk)
                            }
                        }
                    }

                    if !monitor.fixNowActions.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Fix Now")
                                .font(.system(size: 12, weight: .bold, design: .rounded))
                                .foregroundStyle(WolfenceTheme.mutedInk)

                            ForEach(monitor.fixNowActions) { action in
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(action.primaryAction)
                                        .font(.system(size: 12, weight: .semibold, design: .rounded))
                                        .foregroundStyle(action.urgencyTone)
                                    Text("\(action.urgencyLabel) • \(action.ownerSurfaceLabel)")
                                        .font(.system(size: 11, weight: .medium, design: .rounded))
                                        .foregroundStyle(WolfenceTheme.mutedInk)
                                    if let command = action.primaryCommand {
                                        Text(command)
                                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                                            .foregroundStyle(WolfenceTheme.secondaryInk)
                                    }
                                }
                            }
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
            VStack(alignment: .leading, spacing: 12) {
                if let scope = monitor.pushPreview?.scanScope {
                    InfoRow(label: "Discovered", value: "\(scope.discoveredFiles)")
                    InfoRow(label: "Scanned", value: "\(scope.scannedFiles)")
                    InfoRow(label: "Ignored", value: "\(scope.ignoredFiles)")

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
            VStack(alignment: .leading, spacing: 12) {
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
                        .padding(.vertical, 10)
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
        Group {
            if let logoImage = NSImage(contentsOf: wolfHeaderLogoURL) {
                Image(nsImage: logoImage)
                    .resizable()
                    .scaledToFit()
            } else {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .scaledToFit()
            }
        }
        .frame(width: size, height: size)
        .shadow(color: WolfenceTheme.navy.opacity(0.18), radius: 18, y: 8)
    }

    private var wolfHeaderLogoURL: URL {
        URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("Media/logo.png")
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
        let iconCustomizations = decodeStoredIcons(workspaceRepositoryIcons)

        if storedPaths.isEmpty {
            let fallback = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            guard FileManager.default.fileExists(atPath: fallback.path) else { return }
            await workspace.restore(paths: [fallback.path], selectedID: fallback.path, iconCustomizations: iconCustomizations)
            selectedRepositoryPath = fallback.path
            persistWorkspace()
            return
        }

        await workspace.restore(paths: storedPaths, selectedID: selectedRepositoryPath, iconCustomizations: iconCustomizations)
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
        workspaceRepositoryIcons = encodeStoredIcons(
            Dictionary(uniqueKeysWithValues: workspace.repositories.map { ($0.id, $0.iconCustomization) })
        )
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

    private func decodeStoredIcons(_ rawValue: String) -> [String: RepositoryIconCustomization] {
        guard let data = rawValue.data(using: .utf8) else { return [:] }
        return (try? JSONDecoder().decode([String: RepositoryIconCustomization].self, from: data)) ?? [:]
    }

    private func encodeStoredIcons(_ icons: [String: RepositoryIconCustomization]) -> String {
        let filtered = icons.filter { !$0.value.isEmpty }
        guard let data = try? JSONEncoder().encode(filtered),
              let string = String(data: data, encoding: .utf8) else {
            return "{}"
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

    func restore(paths: [String], selectedID: String?, iconCustomizations: [String: RepositoryIconCustomization]) async {
        let uniquePaths = Array(Set(paths)).sorted()
        repositories = uniquePaths.map { WorkspaceRepository(path: $0, iconCustomization: iconCustomizations[$0] ?? .empty) }
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

    func updateRepositoryIcon(id: String, customization: RepositoryIconCustomization) {
        repositories.first(where: { $0.id == id })?.iconCustomization = customization
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
            WorkspaceRepository(path: "/Users/yoavperetz/Developer/Wolfence", monitor: .preview, iconCustomization: RepositoryIconCustomization(symbol: "WO", color: .action)),
            WorkspaceRepository(path: "/Users/yoavperetz/Developer/Dragon", monitor: .previewSecondary, iconCustomization: RepositoryIconCustomization(symbol: "🐉", color: .alert))
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
    var iconCustomization: RepositoryIconCustomization

    init(path: String, monitor: WolfenceMonitor? = nil, iconCustomization: RepositoryIconCustomization? = nil) {
        self.id = path
        self.path = path
        self.iconCustomization = iconCustomization ?? .empty
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
    let onCustomizeIcon: () -> Void
    let onRemove: () -> Void

    var body: some View {
        Button(action: onSelect) {
            HStack(spacing: 10) {
                RepositorySidebarIcon(repository: repository, size: isCollapsed ? 48 : 22, isSelected: isSelected)

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
            Button("Change Icon") {
                onCustomizeIcon()
            }
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
                    .frame(width: collapsed ? 48 : 18)

                if !collapsed {
                    Text(title)
                        .font(.system(size: 13, weight: .semibold, design: .rounded))
                    Spacer(minLength: 0)
                }
            }
            .foregroundStyle(isSelected ? Color.white : WolfenceTheme.primaryInk)
            .padding(.horizontal, collapsed ? 0 : 12)
            .padding(.vertical, collapsed ? 0 : 9)
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

private struct RepositorySidebarIcon: View {
    let repository: WorkspaceRepository
    let size: CGFloat
    let isSelected: Bool

    var body: some View {
        ZStack {
            if let imagePath = repository.iconCustomization.imagePath,
               let image = NSImage(contentsOfFile: imagePath) {
                Image(nsImage: image)
                    .resizable()
                    .scaledToFill()
            } else {
                RoundedRectangle(cornerRadius: max(10, size * 0.28), style: .continuous)
                    .fill(backgroundColor)

                Text(displaySymbol)
                    .font(.system(size: max(10, size * 0.34), weight: .bold, design: .rounded))
                    .foregroundStyle(textColor)
            }
        }
        .frame(width: size, height: size)
        .clipShape(RoundedRectangle(cornerRadius: max(10, size * 0.28), style: .continuous))
    }

    private var displaySymbol: String {
        let custom = repository.iconCustomization.symbol.trimmingCharacters(in: .whitespacesAndNewlines)
        if !custom.isEmpty {
            return String(custom.prefix(2))
        }
        return String(repository.shortName.prefix(2).uppercased())
    }

    private var backgroundColor: Color {
        let base = repository.iconCustomization.color.color
        return isSelected ? base.opacity(0.95) : base.opacity(0.18)
    }

    private var textColor: Color {
        isSelected ? Color.white : WolfenceTheme.primaryInk
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
    private(set) var lastScanLog = "Scan has not been run yet."
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

    var pushSafetyHeadline: String {
        if errorMessage != nil {
            return "Not Safe To Push"
        }

        switch pushPreview?.decision?.verdict {
        case .block:
            return "Not Safe To Push"
        case .warn:
            return "Push Needs Review"
        case .allow:
            return "Safe To Push"
        case .none:
            return "Push Status Unknown"
        }
    }

    var pushSafetySummary: String {
        if let errorMessage {
            return errorMessage
        }

        switch pushPreview?.decision?.verdict {
        case .block:
            return "Blocking findings or trust failures are present. Resolve them before pushing."
        case .warn:
            return "The repository can move forward, but warnings or exceptions should be reviewed first."
        case .allow:
            return "Current policy, trust, and scan evidence allow this repository to push."
        case .none:
            return "Run a scan to load the latest push-safety decision for this repository."
        }
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

    var githubGovernanceCheck: DoctorCheck? {
        doctorReport?.checks.first { $0.name.localizedCaseInsensitiveContains("github governance") }
    }

    var prioritizedFindings: [Finding] {
        guard let decision = pushPreview?.decision else { return [] }
        let findings = decision.blockingFindings.map(\.finding) + decision.warningFindings.map(\.finding)
        let notInBaseline = findings.filter { !($0.baseline?.accepted ?? false) }
        let acceptedBaseline = findings.filter { $0.baseline?.accepted ?? false }
        return notInBaseline + acceptedBaseline
    }

    var topFinding: Finding? {
        prioritizedFindings.first
    }

    var fixNowActions: [RemediationAdvice] {
        let actions = prioritizedFindings.map(\.remediationAdvice)

        var seen = Set<String>()
        return actions.filter { action in
            seen.insert("\(action.primaryAction)|\(action.urgency)|\(action.ownerSurface)").inserted
        }
        .prefix(3)
        .map { $0 }
    }

    func setRepository(_ url: URL) {
        repositoryURL = url
        errorMessage = nil
        lastScanLog = "Scan has not been run yet."
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

    func scan() async {
        guard let repositoryURL else { return }
        isRefreshing = true
        lastScanLog = "Running `wolf scan push --json` in \(repositoryURL.path)"
        defer { isRefreshing = false }

        do {
            let scanResult = try await WolfenceInspector.scan(at: repositoryURL)
            pushPreview = scanResult.pushPreview
            repoConfiguration = scanResult.repoConfiguration
            receiptPolicy = scanResult.receiptPolicy
            auditEntries = scanResult.auditEntries
            lastScanLog = scanResult.commandLog
            errorMessage = scanResult.pushPreview?.error?.message
            lastUpdated = Date()
        } catch {
            errorMessage = error.localizedDescription
            lastScanLog = error.localizedDescription
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
                scannersRun: 5,
                findingHistory: FindingHistorySummary(newFindings: 0, recurringFindings: 1, issue: nil),
                findingBaseline: FindingBaselineSummary(acceptedFindings: 1, unacceptedFindings: 0, issue: nil)
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
                            remediationAdvice: RemediationAdvice(
                                kind: "restrict-scope",
                                urgency: "before-push",
                                ownerSurface: "workflow",
                                primaryAction: "Reduce workflow secret scope so only the deployment job receives the credential.",
                                primaryCommand: nil,
                                docsRef: "docs/security/detection-model.md"
                            ),
                            fingerprint: "dragon-config-001",
                            history: FindingHistory(status: "recurring", firstSeenUnix: 1_775_760_000, lastSeenUnix: 1_775_769_632, timesSeen: 4),
                            baseline: FindingBaseline(accepted: true, capturedOnUnix: 1_775_700_000)
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

    nonisolated static func scan(at repositoryURL: URL) async throws -> ScanState {
        try await Task.detached(priority: .userInitiated) {
            let repoRoot = repositoryURL
            let scanCommand = try await runPushScan(at: repoRoot)
            let config = try loadRepoConfiguration(at: repoRoot)
            let receiptPolicy = try loadReceiptPolicy(at: repoRoot)
            let auditEntries = try await loadAuditEntries(at: repoRoot)

            return ScanState(
                pushPreview: scanCommand.pushPreview,
                repoConfiguration: config,
                receiptPolicy: receiptPolicy,
                auditEntries: auditEntries,
                commandLog: scanCommand.commandLog
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

    private nonisolated static func runPushScan(at repoRoot: URL) async throws -> ScanCommandResult {
        let arguments = ["scan", "push", "--json"]
        let execution = try runWolfCommand(arguments: arguments, in: repoRoot)
        let commandLog = formatCommandLog(command: execution.commandDescription, output: execution.output)

        guard !execution.output.stdout.isEmpty else {
            throw WolfenceError.commandFailed(commandLog)
        }

        let data = Data(execution.output.stdout.utf8)

        do {
            let preview = try await MainActor.run {
                try JSONDecoder().decode(PushPreviewReport.self, from: data)
            }
            return ScanCommandResult(pushPreview: preview, commandLog: commandLog)
        } catch {
            throw WolfenceError.commandFailed("Failed to decode scan JSON.\n\(commandLog)")
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
        let output = try runWolfCommand(arguments: arguments, in: repoRoot).output
        if !output.stdout.isEmpty {
            return output.stdout.data(using: .utf8)
        }
        return nil
    }

    private nonisolated static func runWolfCommand(arguments: [String], in repoRoot: URL) throws -> CommandExecution {
        if let binary = discoverWolfBinary(in: repoRoot) {
            let output = try shell(binary.path, arguments, in: repoRoot, allowFailure: true, useEnv: false)
            return CommandExecution(commandDescription: ([binary.path] + arguments).joined(separator: " "), output: output)
        }

        let output = try shell("wolf", arguments, in: repoRoot, allowFailure: true)
        return CommandExecution(commandDescription: (["wolf"] + arguments).joined(separator: " "), output: output)
    }

    private nonisolated static func formatCommandLog(command: String, output: ShellOutput) -> String {
        var lines = [
            "Command: \(command)",
            "Exit Status: \(output.status)"
        ]

        if !output.stderr.isEmpty {
            lines.append("stderr:")
            lines.append(output.stderr)
        }

        if !output.stdout.isEmpty {
            lines.append("stdout:")
            lines.append(output.stdout)
        }

        if output.stdout.isEmpty && output.stderr.isEmpty {
            lines.append("No output was produced.")
        }

        return lines.joined(separator: "\n")
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

private struct ScanState: Sendable {
    let pushPreview: PushPreviewReport?
    let repoConfiguration: RepoConfiguration
    let receiptPolicy: ReceiptPolicy
    let auditEntries: [AuditEntry]
    let commandLog: String
}

private struct ScanCommandResult: Sendable {
    let pushPreview: PushPreviewReport
    let commandLog: String
}

private struct CommandExecution: Sendable {
    let commandDescription: String
    let output: ShellOutput
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

    var displayLabel: String {
        rawValue.capitalized
    }

    var tone: Color {
        switch self {
        case .pass:
            return WolfenceTheme.ok
        case .warn:
            return WolfenceTheme.caution
        case .fail:
            return WolfenceTheme.alert
        case .info:
            return WolfenceTheme.steel
        }
    }
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
    var findingHistory: FindingHistorySummary? = nil
    var findingBaseline: FindingBaselineSummary? = nil

    enum CodingKeys: String, CodingKey {
        case findings
        case discoveredFiles = "discovered_files"
        case scannedFiles = "scanned_files"
        case ignoredFiles = "ignored_files"
        case scannersRun = "scanners_run"
        case findingHistory = "finding_history"
        case findingBaseline = "finding_baseline"
    }
}

private struct FindingHistorySummary: Decodable, Sendable {
    let newFindings: Int
    let recurringFindings: Int
    let issue: String?

    enum CodingKeys: String, CodingKey {
        case newFindings = "new_findings"
        case recurringFindings = "recurring_findings"
        case issue
    }
}

private struct FindingBaselineSummary: Decodable, Sendable {
    let acceptedFindings: Int
    let unacceptedFindings: Int
    let issue: String?

    enum CodingKeys: String, CodingKey {
        case acceptedFindings = "accepted_findings"
        case unacceptedFindings = "unaccepted_findings"
        case issue
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
    let remediationAdvice: RemediationAdvice
    let fingerprint: String
    var history: FindingHistory? = nil
    var baseline: FindingBaseline? = nil

    enum CodingKeys: String, CodingKey {
        case scanner, severity, confidence, category, file, line, title, detail, remediation, fingerprint, history, baseline
        case remediationAdvice = "remediation_advice"
    }
}

private struct FindingHistory: Decodable, Sendable {
    let status: String
    let firstSeenUnix: Int
    let lastSeenUnix: Int
    let timesSeen: Int

    enum CodingKeys: String, CodingKey {
        case status
        case firstSeenUnix = "first_seen_unix"
        case lastSeenUnix = "last_seen_unix"
        case timesSeen = "times_seen"
    }

    var statusLabel: String {
        status.replacingOccurrences(of: "-", with: " ").capitalized
    }

    var tone: Color {
        switch status {
        case "new":
            return WolfenceTheme.caution
        default:
            return WolfenceTheme.steel
        }
    }
}

private struct FindingBaseline: Decodable, Sendable {
    let accepted: Bool
    let capturedOnUnix: Int?

    enum CodingKeys: String, CodingKey {
        case accepted
        case capturedOnUnix = "captured_on_unix"
    }

    var statusLabel: String {
        accepted ? "Accepted Starting State" : "Needs Review"
    }

    var tone: Color {
        accepted ? WolfenceTheme.steel : WolfenceTheme.caution
    }
}

private struct RemediationAdvice: Decodable, Identifiable, Sendable {
    var id: String { primaryAction + "|" + urgency + "|" + ownerSurface }
    let kind: String
    let urgency: String
    let ownerSurface: String
    let primaryAction: String
    let primaryCommand: String?
    let docsRef: String?

    enum CodingKeys: String, CodingKey {
        case kind, urgency
        case ownerSurface = "owner_surface"
        case primaryAction = "primary_action"
        case primaryCommand = "primary_command"
        case docsRef = "docs_ref"
    }

    var urgencyLabel: String {
        urgency.replacingOccurrences(of: "-", with: " ").capitalized
    }

    var ownerSurfaceLabel: String {
        ownerSurface.replacingOccurrences(of: "-", with: " ").capitalized
    }

    var urgencyTone: Color {
        switch urgency {
        case "immediate":
            return WolfenceTheme.alert
        case "before-push":
            return WolfenceTheme.caution
        default:
            return WolfenceTheme.secondaryInk
        }
    }
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
    enum Emphasis {
        case hero
        case section
    }

    let title: String?
    let subtitle: String?
    let emphasis: Emphasis
    @ViewBuilder let content: Content

    init(
        title: String? = nil,
        subtitle: String? = nil,
        emphasis: Emphasis = .section,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.subtitle = subtitle
        self.emphasis = emphasis
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
        .padding(.vertical, emphasis == .hero ? 6 : 14)
        .frame(maxWidth: .infinity, alignment: .leading)
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
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 16)
    }
}

private struct WolfenceActionButtonStyle: ButtonStyle {
    enum Prominence {
        case primary
        case secondary
    }

    let tone: Color
    var prominence: Prominence = .secondary

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold, design: .rounded))
            .foregroundStyle(prominence == .primary ? Color.white : WolfenceTheme.primaryInk)
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(backgroundFill(pressed: configuration.isPressed))
                    .overlay(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .stroke(tone.opacity(prominence == .primary ? 0.18 : 0.22), lineWidth: 1)
                    )
            )
            .opacity(configuration.isPressed ? 0.92 : 1)
            .scaleEffect(configuration.isPressed ? 0.985 : 1)
            .animation(.snappy(duration: 0.14, extraBounce: 0), value: configuration.isPressed)
    }

    private func backgroundFill(pressed: Bool) -> Color {
        switch prominence {
        case .primary:
            return tone.opacity(pressed ? 0.82 : 0.94)
        case .secondary:
            return tone.opacity(pressed ? 0.12 : 0.16)
        }
    }
}

private struct WolfenceIconButtonStyle: ButtonStyle {
    let tone: Color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(tone)
            .frame(width: 30, height: 30)
            .background(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(tone.opacity(configuration.isPressed ? 0.14 : 0.1))
                    .overlay(
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .stroke(tone.opacity(0.18), lineWidth: 1)
                    )
            )
            .scaleEffect(configuration.isPressed ? 0.96 : 1)
            .animation(.snappy(duration: 0.14, extraBounce: 0), value: configuration.isPressed)
    }
}

private struct RepositoryIconEditorSheet: View {
    let repository: WorkspaceRepository
    let onSave: (RepositoryIconCustomization) -> Void
    let onCancel: () -> Void

    @State private var symbol: String
    @State private var selectedColor: Color
    @State private var imagePath: String?

    init(repository: WorkspaceRepository, onSave: @escaping (RepositoryIconCustomization) -> Void, onCancel: @escaping () -> Void) {
        self.repository = repository
        self.onSave = onSave
        self.onCancel = onCancel
        _symbol = State(initialValue: repository.iconCustomization.symbol)
        _selectedColor = State(initialValue: repository.iconCustomization.color.color)
        _imagePath = State(initialValue: repository.iconCustomization.imagePath)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Change Icon")
                .font(.system(size: 24, weight: .semibold, design: .serif))
                .foregroundStyle(WolfenceTheme.ivory)

            HStack(spacing: 18) {
                iconPreview

                VStack(alignment: .leading, spacing: 10) {
                    Text(repository.displayTitle)
                        .font(.system(size: 16, weight: .semibold, design: .rounded))
                        .foregroundStyle(WolfenceTheme.ivory)

                    Text("Use letters, emoji, a color tint, or a custom image.")
                        .font(.system(size: 13, weight: .medium, design: .rounded))
                        .foregroundStyle(WolfenceTheme.parchment)
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Letters or Emoji")
                    .font(.system(size: 12, weight: .bold, design: .rounded))
                    .foregroundStyle(WolfenceTheme.parchment)

                TextField("WO or 🐺", text: $symbol)
                    .textFieldStyle(.roundedBorder)
                    .foregroundStyle(WolfenceTheme.ivory)
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Color")
                    .font(.system(size: 12, weight: .bold, design: .rounded))
                    .foregroundStyle(WolfenceTheme.parchment)

                ColorPicker("Icon Color", selection: $selectedColor, supportsOpacity: false)
                    .labelsHidden()
            }

            HStack(spacing: 12) {
                Button("Choose Image") {
                    chooseImage()
                }
                .buttonStyle(WolfenceActionButtonStyle(tone: WolfenceTheme.navy, prominence: .primary))

                Button("Use Text Icon") {
                    imagePath = nil
                }
                .buttonStyle(WolfenceActionButtonStyle(tone: WolfenceTheme.steel, prominence: .primary))

                Button("Reset") {
                    symbol = ""
                    selectedColor = WolfenceTheme.action
                    imagePath = nil
                }
                .buttonStyle(WolfenceActionButtonStyle(tone: WolfenceTheme.steel, prominence: .primary))
            }

            HStack(spacing: 12) {
                Spacer()

                Button("Cancel") {
                    onCancel()
                }
                .buttonStyle(WolfenceActionButtonStyle(tone: WolfenceTheme.steel, prominence: .primary))

                Button("Save") {
                    onSave(
                        RepositoryIconCustomization(
                            symbol: symbol,
                            color: RepositoryIconTint(selectedColor),
                            imagePath: imagePath
                        )
                    )
                }
                .buttonStyle(WolfenceActionButtonStyle(tone: WolfenceTheme.action, prominence: .primary))
            }
        }
        .padding(24)
        .frame(width: 440)
    }

    private var iconPreview: some View {
        ZStack {
            if let imagePath, let image = NSImage(contentsOfFile: imagePath) {
                Image(nsImage: image)
                    .resizable()
                    .scaledToFill()
            } else {
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .fill(RepositoryIconTint(selectedColor).color)

                Text(previewSymbol)
                    .font(.system(size: 28, weight: .bold, design: .rounded))
                    .foregroundStyle(Color.white)
            }
        }
        .frame(width: 80, height: 80)
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private var previewSymbol: String {
        let trimmed = symbol.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            return String(trimmed.prefix(2))
        }
        return String(repository.shortName.prefix(2).uppercased())
    }

    private func chooseImage() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.image]
        panel.prompt = "Choose Icon"

        if panel.runModal() == .OK {
            imagePath = panel.url?.path
        }
    }
}

private struct RepositoryIconCustomization: Codable, Equatable {
    var symbol: String = ""
    var color: RepositoryIconTint = .action
    var imagePath: String?

    static let empty = RepositoryIconCustomization()

    var isEmpty: Bool {
        symbol.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && imagePath == nil && color == .action
    }
}

private struct RepositoryIconTint: Codable, Equatable {
    var red: Double
    var green: Double
    var blue: Double
    var opacity: Double

    init(red: Double, green: Double, blue: Double, opacity: Double = 1) {
        self.red = red
        self.green = green
        self.blue = blue
        self.opacity = opacity
    }

    init(_ color: Color) {
        let resolved = NSColor(color)
        let converted = resolved.usingColorSpace(.deviceRGB) ?? NSColor.controlAccentColor
        self.red = Double(converted.redComponent)
        self.green = Double(converted.greenComponent)
        self.blue = Double(converted.blueComponent)
        self.opacity = Double(converted.alphaComponent)
    }

    var color: Color {
        Color(.sRGB, red: red, green: green, blue: blue, opacity: opacity)
    }

    static let action = RepositoryIconTint(red: 0.14, green: 0.26, blue: 0.44)
    static let alert = RepositoryIconTint(red: 0.66, green: 0.25, blue: 0.22)
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
