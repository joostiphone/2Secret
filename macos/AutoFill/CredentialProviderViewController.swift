import AppKit
import AuthenticationServices

/// AutoFill for passwords, passkeys and verification codes on the Mac, in
/// Safari and other apps (System Settings → General → AutoFill & Passwords →
/// 2Secret). Like the iOS extension it fills from the cache the 2Secret app
/// keeps while unlocking with Touch ID is on (see ios/AutoFill/Vault.swift);
/// it cannot change the vault. The panel looks like the app: its colours
/// (`Brand`), its logo, its theme, and the websites' icons.
@objc(CredentialProviderViewController)
final class CredentialProviderViewController: ASCredentialProviderViewController,
    NSTableViewDataSource, NSTableViewDelegate, NSSearchFieldDelegate
{
    private enum Row {
        case header(String)
        case login(Login)
        case passkey(Login, Passkey)
        case code(Login)

        var selectable: Bool {
            if case .header = self { return false }
            return true
        }
    }

    private let hostLabel = NSTextField(labelWithString: "")
    private let searchField = NSSearchField()
    private let card = ColorView(color: Brand.panel)
    private let tableView = NSTableView()
    private let scrollView = NSScrollView()
    private let stateStack = NSStackView()
    private let bigLogo = LogoView(size: 56)
    private let spinner = NSProgressIndicator()
    private let messageLabel = NSTextField(wrappingLabelWithString: L.unlocking)
    private let messageHost = NSTextField(labelWithString: "")
    private let messageButton = NSButton(title: L.close, target: nil, action: nil)
    private var cache: AutofillCache?
    private var serviceIdentifiers: [ASCredentialServiceIdentifier] = []
    private var passkeyParameters: ASPasskeyCredentialRequestParameters?
    /// The list is for a verification code field (macOS 15).
    private var oneTimeCodes = false
    private var rows: [Row] = []
    private var messageAction: (() -> Void)?

    /// The website the request is for, as shown in the header and the Touch
    /// ID dialog (`www.` left out).
    private var host: String? {
        let hosts = Vault.hosts(serviceIdentifiers).map { h -> String in
            h.hasPrefix("www.") ? String(h.dropFirst(4)) : h
        }
        return hosts.sorted().first
    }

    // MARK: - Layout

    override func loadView() {
        // No nib: the view is built in code, on the app's background colour.
        let root = ColorView(color: Brand.bg)
        root.frame = NSRect(x: 0, y: 0, width: 420, height: 480)
        view = root
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        preferredContentSize = NSSize(width: 420, height: 480)
        // The app's theme; "system" follows macOS.
        switch Vault.theme() {
        case "dark": view.appearance = NSAppearance(named: .darkAqua)
        case "light": view.appearance = NSAppearance(named: .aqua)
        default: break
        }

        // Header: logo, name, the website, Cancel.
        let logo = LogoView(size: 28)
        let title = NSTextField(labelWithString: "2Secret")
        title.font = .systemFont(ofSize: 15, weight: .semibold)
        title.textColor = Brand.text
        hostLabel.font = .systemFont(ofSize: 12)
        hostLabel.textColor = Brand.muted
        hostLabel.lineBreakMode = .byTruncatingMiddle
        hostLabel.isHidden = true
        let names = NSStackView(views: [title, hostLabel])
        names.orientation = .vertical
        names.alignment = .leading
        names.spacing = 1
        let cancel = NSButton(title: L.cancel, target: self, action: #selector(cancelTapped))
        cancel.isBordered = false
        cancel.font = .systemFont(ofSize: 13)
        cancel.contentTintColor = Brand.accent
        cancel.keyEquivalent = "\u{1b}"
        cancel.setContentHuggingPriority(.required, for: .horizontal)
        let header = NSStackView(views: [logo, names, cancel])
        header.orientation = .horizontal
        header.alignment = .centerY
        header.spacing = 10
        names.setContentHuggingPriority(.defaultLow, for: .horizontal)
        names.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        searchField.placeholderString = L.search
        searchField.delegate = self
        // Also for the clear button, which sends no text change.
        searchField.target = self
        searchField.action = #selector(searchChanged)
        searchField.isHidden = true

        // The list, in a card like the app's panels.
        card.cornerRadius = Brand.radius
        card.borderColor = Brand.border
        card.isHidden = true
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("row"))
        column.resizingMask = .autoresizingMask
        tableView.addTableColumn(column)
        tableView.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        tableView.headerView = nil
        tableView.style = .plain
        tableView.backgroundColor = .clear
        tableView.gridStyleMask = []
        tableView.intercellSpacing = NSSize(width: 0, height: 0)
        tableView.selectionHighlightStyle = .regular
        tableView.dataSource = self
        tableView.delegate = self
        tableView.target = self
        tableView.action = #selector(rowClicked)
        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        scrollView.drawsBackground = false
        scrollView.contentInsets = NSEdgeInsets(top: 4, left: 0, bottom: 4, right: 0)
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(scrollView)
        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: card.topAnchor, constant: 1),
            scrollView.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 1),
            scrollView.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -1),
            scrollView.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -1),
        ])

        // Unlocking, and messages: logo, spinner, text, website, a button.
        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.isDisplayedWhenStopped = false
        spinner.startAnimation(nil)
        messageLabel.alignment = .center
        messageLabel.font = .systemFont(ofSize: 13)
        messageLabel.textColor = Brand.text
        messageLabel.preferredMaxLayoutWidth = 340
        messageHost.alignment = .center
        messageHost.font = .systemFont(ofSize: 12)
        messageHost.textColor = Brand.muted
        messageHost.isHidden = true
        messageButton.target = self
        messageButton.action = #selector(messageButtonTapped)
        messageButton.isHidden = true
        for subview in [bigLogo, spinner, messageLabel, messageHost, messageButton] {
            stateStack.addArrangedSubview(subview)
        }
        stateStack.orientation = .vertical
        stateStack.alignment = .centerX
        stateStack.spacing = 12
        stateStack.setCustomSpacing(18, after: bigLogo)

        for subview in [header, searchField, card, stateStack] as [NSView] {
            subview.translatesAutoresizingMaskIntoConstraints = false
            view.addSubview(subview)
        }
        NSLayoutConstraint.activate([
            header.topAnchor.constraint(equalTo: view.topAnchor, constant: 14),
            header.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            header.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            searchField.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 12),
            searchField.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            searchField.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            card.topAnchor.constraint(equalTo: searchField.bottomAnchor, constant: 10),
            card.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            card.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            card.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -16),
            stateStack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stateStack.centerYAnchor.constraint(equalTo: view.centerYAnchor, constant: 16),
            stateStack.leadingAnchor.constraint(greaterThanOrEqualTo: view.leadingAnchor, constant: 32),
            stateStack.trailingAnchor.constraint(lessThanOrEqualTo: view.trailingAnchor, constant: -32),
            messageLabel.widthAnchor.constraint(lessThanOrEqualToConstant: 340),
        ])
    }

    override func viewDidAppear() {
        super.viewDidAppear()
        if !searchField.isHidden {
            view.window?.makeFirstResponder(searchField)
        }
    }

    /// Show the website in the header and under the unlocking message.
    private func showHost() {
        _ = view
        let site = host ?? ""
        hostLabel.stringValue = site
        hostLabel.isHidden = site.isEmpty
        messageHost.stringValue = L.forSite(site)
        messageHost.isHidden = site.isEmpty
    }

    // MARK: - Requests from the system

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        self.serviceIdentifiers = serviceIdentifiers
        showHost()
        unlock { [weak self] _ in self?.reload() }
    }

    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier],
        requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        self.serviceIdentifiers = serviceIdentifiers
        passkeyParameters = requestParameters
        showHost()
        unlock { [weak self] _ in self?.reload() }
    }

    /// A verification code field: the logins with a one-time password.
    @available(macOS 15.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        self.serviceIdentifiers = serviceIdentifiers
        oneTimeCodes = true
        showHost()
        unlock { [weak self] _ in self?.reload() }
    }

    /// A suggestion in the password menu was chosen. The key needs Touch ID,
    /// so macOS has to show our interface first.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        extensionContext.cancelRequest(withError: Self.error(.userInteractionRequired))
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        serviceIdentifiers = [credentialRequest.credentialIdentity.serviceIdentifier]
        showHost()
        unlock { [weak self] cache in
            guard let self else { return }
            if let request = credentialRequest as? ASPasskeyCredentialRequest,
               let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
            {
                for login in cache.logins {
                    for passkey in login.passkeys where Vault.data(base64url: passkey.credentialId) == identity.credentialID {
                        self.complete(passkey: passkey, clientDataHash: request.clientDataHash)
                        return
                    }
                }
            } else if let identity = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity,
                      let login = cache.logins.first(where: { $0.id == identity.recordIdentifier })
            {
                self.complete(login: login)
                return
            } else if #available(macOS 15.0, *),
                      let identity = credentialRequest.credentialIdentity as? ASOneTimeCodeCredentialIdentity,
                      let login = cache.logins.first(where: { $0.id == identity.recordIdentifier && $0.totp != nil })
            {
                self.complete(code: login)
                return
            }
            self.extensionContext.cancelRequest(withError: Self.error(.credentialIdentityNotFound))
        }
    }

    override func prepareInterfaceForExtensionConfiguration() {
        show(message: L.configured, button: L.close) { [weak self] in
            self?.extensionContext.completeExtensionConfigurationRequest()
        }
    }

    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        show(message: L.registerElsewhere, button: L.close) { [weak self] in
            self?.extensionContext.cancelRequest(withError: Self.error(.failed))
        }
    }

    // MARK: - Unlocking and answering

    private func unlock(then use: @escaping (AutofillCache) -> Void) {
        if let cache {
            use(cache)
            return
        }
        let reason = L.reason(host: host)
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try Vault.load(reason: reason) }
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                switch result {
                case let .success(cache):
                    self.cache = cache
                    use(cache)
                case let .failure(error):
                    switch error as? VaultError {
                    case .cancelled:
                        self.extensionContext.cancelRequest(withError: Self.error(.userCanceled))
                    case .passwordNeeded:
                        self.show(message: L.passwordNeeded, button: L.close) { [weak self] in self?.cancelTapped() }
                    case .notSetUp:
                        self.show(message: L.notSetUp, button: L.close) { [weak self] in self?.cancelTapped() }
                    default:
                        self.show(message: "\(error)", button: L.close) { [weak self] in self?.cancelTapped() }
                    }
                }
            }
        }
    }

    private func complete(login: Login) {
        let credential = ASPasswordCredential(user: login.username, password: login.password)
        extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
    }

    private func complete(passkey: Passkey, clientDataHash: Data) {
        do {
            let credential = try Vault.assertion(passkey, clientDataHash: clientDataHash)
            extensionContext.completeAssertionRequest(using: credential, completionHandler: nil)
        } catch {
            extensionContext.cancelRequest(withError: Self.error(.failed))
        }
    }

    private func complete(code login: Login) {
        guard #available(macOS 15.0, *), let code = login.totp?.code() else {
            extensionContext.cancelRequest(withError: Self.error(.failed))
            return
        }
        extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code), completionHandler: nil)
    }

    private func choose(_ row: Row) {
        switch row {
        case .header:
            break
        case let .login(login):
            complete(login: login)
        case let .passkey(_, passkey):
            guard let params = passkeyParameters else { return }
            complete(passkey: passkey, clientDataHash: params.clientDataHash)
        case let .code(login):
            complete(code: login)
        }
    }

    @objc private func cancelTapped() {
        extensionContext.cancelRequest(withError: Self.error(.userCanceled))
    }

    private static func error(_ code: ASExtensionError.Code) -> NSError {
        NSError(domain: ASExtensionErrorDomain, code: code.rawValue)
    }

    // MARK: - Messages

    private func show(message: String, button: String, action: @escaping () -> Void) {
        _ = view
        spinner.stopAnimation(nil)
        bigLogo.isHidden = false
        messageLabel.stringValue = message
        messageLabel.textColor = Brand.muted
        messageHost.isHidden = true
        messageButton.title = button
        messageButton.isHidden = false
        messageButton.keyEquivalent = "\r"
        messageAction = action
        stateStack.isHidden = false
        card.isHidden = true
        searchField.isHidden = true
    }

    @objc private func messageButtonTapped() {
        messageAction?()
    }

    // MARK: - The list

    private func reload() {
        guard let cache else { return }
        _ = view
        let query = searchField.stringValue.trimmingCharacters(in: .whitespaces).lowercased()
        let wanted = Vault.candidates(serviceIdentifiers)
        let hosts = Vault.hosts(serviceIdentifiers)
        let matchesQuery: (Login) -> Bool = { login in
            query.isEmpty || login.title.lowercased().contains(query) || login.username.lowercased().contains(query)
                || (login.domains + (login.exactHosts ?? [])).contains { $0.contains(query) }
        }
        var rows: [Row] = []

        if let params = passkeyParameters {
            let allowed = Set(params.allowedCredentials)
            var passkeys: [Row] = []
            for login in cache.logins {
                for passkey in login.passkeys where passkey.rpId == params.relyingPartyIdentifier {
                    if allowed.isEmpty || Vault.data(base64url: passkey.credentialId).map(allowed.contains) == true {
                        passkeys.append(.passkey(login, passkey))
                    }
                }
            }
            if !passkeys.isEmpty { rows += [Row.header(L.passkeys)] + passkeys }
        }
        // Logins with a password, or with a one-time password for a code field.
        let listed = cache.logins.filter { (oneTimeCodes ? $0.totp != nil : !$0.password.isEmpty) && matchesQuery($0) }
        let row: (Login) -> Row = oneTimeCodes ? Row.code : Row.login
        let suggested = listed.filter { $0.isFor(candidates: wanted, hosts: hosts) }
        let others = listed.filter { !$0.isFor(candidates: wanted, hosts: hosts) }
        if !suggested.isEmpty { rows += [Row.header(L.suggested)] + suggested.map(row) }
        if !others.isEmpty { rows += [Row.header(L.all)] + others.map(row) }
        self.rows = rows
        tableView.reloadData()

        spinner.stopAnimation(nil)
        searchField.isHidden = false
        card.isHidden = rows.isEmpty
        stateStack.isHidden = !rows.isEmpty
        bigLogo.isHidden = true
        messageLabel.stringValue = oneTimeCodes && query.isEmpty ? L.noCodes : L.nothing
        messageLabel.textColor = Brand.muted
        messageHost.isHidden = true
        messageButton.isHidden = true
        select(rows.firstIndex(where: \.selectable))
        if view.window?.firstResponder !== searchField.currentEditor() {
            view.window?.makeFirstResponder(searchField)
        }
    }

    private func select(_ index: Int?) {
        guard let index else {
            tableView.deselectAll(nil)
            return
        }
        tableView.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
        tableView.scrollRowToVisible(index)
    }

    /// The next selectable row above or below the selected one.
    private func move(by step: Int) {
        var index = tableView.selectedRow + step
        while rows.indices.contains(index) {
            if rows[index].selectable {
                select(index)
                return
            }
            index += step
        }
    }

    @objc private func rowClicked() {
        let index = tableView.clickedRow
        guard rows.indices.contains(index) else { return }
        choose(rows[index])
    }

    func controlTextDidChange(_: Notification) {
        reload()
    }

    @objc private func searchChanged() {
        reload()
    }

    /// Arrow keys move through the list while typing; Return fills.
    func control(_: NSControl, textView _: NSTextView, doCommandBy selector: Selector) -> Bool {
        switch selector {
        case #selector(NSResponder.moveDown(_:)):
            move(by: 1)
        case #selector(NSResponder.moveUp(_:)):
            move(by: -1)
        case #selector(NSResponder.insertNewline(_:)):
            if rows.indices.contains(tableView.selectedRow) {
                choose(rows[tableView.selectedRow])
            }
        default:
            return false
        }
        return true
    }

    func numberOfRows(in _: NSTableView) -> Int {
        rows.count
    }

    func tableView(_: NSTableView, shouldSelectRow row: Int) -> Bool {
        rows.indices.contains(row) && rows[row].selectable
    }

    func tableView(_: NSTableView, heightOfRow row: Int) -> CGFloat {
        rows.indices.contains(row) && !rows[row].selectable ? 28 : 46
    }

    func tableView(_: NSTableView, rowViewForRow _: Int) -> NSTableRowView? {
        BrandRowView()
    }

    func tableView(_: NSTableView, viewFor _: NSTableColumn?, row: Int) -> NSView? {
        guard rows.indices.contains(row) else { return nil }
        switch rows[row] {
        case let .header(title):
            let label = NSTextField(labelWithString: title.uppercased())
            label.font = .systemFont(ofSize: 11, weight: .semibold)
            label.textColor = Brand.muted
            return cell([label], inset: 14)
        case let .login(login):
            return item(icon: login.icon, symbol: "key.fill", title: login.title, subtitle: login.username)
        case let .passkey(login, passkey):
            return item(
                icon: login.icon,
                symbol: "person.badge.key.fill",
                title: passkey.userName.isEmpty ? login.username : passkey.userName,
                subtitle: "\(login.title) · \(passkey.rpId)"
            )
        case let .code(login):
            return item(icon: login.icon, symbol: "clock.fill", title: login.title, subtitle: login.username)
        }
    }

    private func item(icon: String?, symbol: String, title: String, subtitle: String) -> NSView {
        let titleLabel = NSTextField(labelWithString: title)
        titleLabel.font = .systemFont(ofSize: 13, weight: .medium)
        titleLabel.textColor = Brand.text
        titleLabel.lineBreakMode = .byTruncatingTail
        let subtitleLabel = NSTextField(labelWithString: subtitle)
        subtitleLabel.font = .systemFont(ofSize: 11)
        subtitleLabel.textColor = Brand.muted
        subtitleLabel.lineBreakMode = .byTruncatingTail
        let texts = NSStackView(views: [titleLabel, subtitleLabel])
        texts.orientation = .vertical
        texts.alignment = .leading
        texts.spacing = 1
        return cell([IconView(icon: icon, symbol: symbol), texts], inset: 10)
    }

    /// A row: the views side by side, vertically centred.
    private func cell(_ views: [NSView], inset: CGFloat) -> NSView {
        let row = NSStackView(views: views)
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 10
        let cell = NSTableCellView()
        row.translatesAutoresizingMaskIntoConstraints = false
        cell.addSubview(row)
        NSLayoutConstraint.activate([
            row.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: inset),
            row.trailingAnchor.constraint(lessThanOrEqualTo: cell.trailingAnchor, constant: -inset),
            row.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
        ])
        return cell
    }
}

// MARK: - Views in the app's look

/// A view painted in one of the app's colours, optionally rounded with a
/// border; drawn, not layered, so it follows light and dark.
class ColorView: NSView {
    var color: NSColor { didSet { needsDisplay = true } }
    var cornerRadius: CGFloat = 0 { didSet { needsDisplay = true } }
    var borderColor: NSColor? { didSet { needsDisplay = true } }

    init(color: NSColor) {
        self.color = color
        super.init(frame: .zero)
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("not used")
    }

    override var isFlipped: Bool { true }

    override func draw(_: NSRect) {
        let rect = borderColor == nil ? bounds : bounds.insetBy(dx: 0.5, dy: 0.5)
        let path = NSBezierPath(roundedRect: rect, xRadius: cornerRadius, yRadius: cornerRadius)
        color.setFill()
        path.fill()
        if let borderColor {
            borderColor.setStroke()
            path.lineWidth = 1
            path.stroke()
        }
    }
}

/// The app icon, rounded like an app icon.
final class LogoView: NSImageView {
    init(size: CGFloat) {
        super.init(frame: NSRect(x: 0, y: 0, width: size, height: size))
        image = Brand.logo
        imageScaling = .scaleProportionallyUpOrDown
        wantsLayer = true
        layer?.cornerRadius = size * 0.24
        layer?.masksToBounds = true
        translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            widthAnchor.constraint(equalToConstant: size),
            heightAnchor.constraint(equalToConstant: size),
        ])
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("not used")
    }
}

/// A login's website icon, or a symbol in the accent colour on a soft tile.
final class IconView: ColorView {
    init(icon: String?, symbol: String) {
        let website = Vault.imageData(dataURL: icon).flatMap(NSImage.init(data:))
        super.init(color: website == nil ? Brand.accentSoft : .clear)
        cornerRadius = 7
        let image = website ?? NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?
            .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 13, weight: .medium))
        let imageView = NSImageView(image: image ?? NSImage())
        imageView.imageScaling = .scaleProportionallyUpOrDown
        imageView.contentTintColor = Brand.accent
        imageView.wantsLayer = true
        imageView.layer?.cornerRadius = 6
        imageView.layer?.masksToBounds = true
        imageView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(imageView)
        let side: CGFloat = website == nil ? 16 : 28
        translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            widthAnchor.constraint(equalToConstant: 28),
            heightAnchor.constraint(equalToConstant: 28),
            imageView.centerXAnchor.constraint(equalTo: centerXAnchor),
            imageView.centerYAnchor.constraint(equalTo: centerYAnchor),
            imageView.widthAnchor.constraint(equalToConstant: side),
            imageView.heightAnchor.constraint(equalToConstant: side),
        ])
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("not used")
    }
}

/// A row whose selection is the app's: a rounded, soft highlight.
final class BrandRowView: NSTableRowView {
    override var isEmphasized: Bool {
        get { false }
        set {}
    }

    override func drawSelection(in _: NSRect) {
        guard selectionHighlightStyle != .none else { return }
        Brand.selected.setFill()
        NSBezierPath(roundedRect: bounds.insetBy(dx: 6, dy: 1), xRadius: 8, yRadius: 8).fill()
    }
}
