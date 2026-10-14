import AppKit
import AuthenticationServices

/// AutoFill for passwords and passkeys on the Mac, in Safari and other apps
/// (System Settings → General → AutoFill & Passwords → 2Secret). Like the iOS
/// extension it fills from the cache the 2Secret app keeps while unlocking
/// with Touch ID is on (see ios/AutoFill/Vault.swift); it cannot change the
/// vault.
@objc(CredentialProviderViewController)
final class CredentialProviderViewController: ASCredentialProviderViewController,
    NSTableViewDataSource, NSTableViewDelegate, NSSearchFieldDelegate
{
    private enum Row {
        case header(String)
        case login(Login)
        case passkey(Login, Passkey)

        var selectable: Bool {
            if case .header = self { return false }
            return true
        }
    }

    private let searchField = NSSearchField()
    private let messageLabel = NSTextField(wrappingLabelWithString: L.unlocking)
    private let messageButton = NSButton(title: L.close, target: nil, action: nil)
    private let tableView = NSTableView()
    private let scrollView = NSScrollView()
    private var cache: AutofillCache?
    private var serviceIdentifiers: [ASCredentialServiceIdentifier] = []
    private var passkeyParameters: ASPasskeyCredentialRequestParameters?
    private var rows: [Row] = []
    private var messageAction: (() -> Void)?

    // MARK: - Layout

    override func loadView() {
        // No nib: the view is built in code.
        view = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 460))
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        preferredContentSize = NSSize(width: 420, height: 460)

        let title = NSTextField(labelWithString: "2Secret")
        title.font = .systemFont(ofSize: NSFont.systemFontSize + 2, weight: .semibold)
        let cancel = NSButton(title: L.cancel, target: self, action: #selector(cancelTapped))
        cancel.keyEquivalent = "\u{1b}"

        searchField.placeholderString = L.search
        searchField.delegate = self
        // Also for the clear button, which sends no text change.
        searchField.target = self
        searchField.action = #selector(searchChanged)
        searchField.isHidden = true

        messageLabel.alignment = .center
        messageLabel.textColor = .secondaryLabelColor
        messageButton.target = self
        messageButton.action = #selector(messageButtonTapped)
        messageButton.isHidden = true

        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("row"))
        column.resizingMask = .autoresizingMask
        tableView.addTableColumn(column)
        tableView.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        tableView.headerView = nil
        tableView.style = .inset
        tableView.dataSource = self
        tableView.delegate = self
        tableView.target = self
        tableView.action = #selector(rowClicked)
        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        scrollView.drawsBackground = false
        scrollView.isHidden = true

        for subview in [title, cancel, searchField, scrollView, messageLabel, messageButton] as [NSView] {
            subview.translatesAutoresizingMaskIntoConstraints = false
            view.addSubview(subview)
        }
        NSLayoutConstraint.activate([
            title.topAnchor.constraint(equalTo: view.topAnchor, constant: 14),
            title.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            cancel.centerYAnchor.constraint(equalTo: title.centerYAnchor),
            cancel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            searchField.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 12),
            searchField.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            searchField.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            scrollView.topAnchor.constraint(equalTo: searchField.bottomAnchor, constant: 8),
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            messageLabel.centerYAnchor.constraint(equalTo: view.centerYAnchor, constant: 10),
            messageLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 32),
            messageLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -32),
            messageButton.topAnchor.constraint(equalTo: messageLabel.bottomAnchor, constant: 14),
            messageButton.centerXAnchor.constraint(equalTo: view.centerXAnchor),
        ])
    }

    override func viewDidAppear() {
        super.viewDidAppear()
        if !searchField.isHidden {
            view.window?.makeFirstResponder(searchField)
        }
    }

    // MARK: - Requests from the system

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        self.serviceIdentifiers = serviceIdentifiers
        unlock { [weak self] _ in self?.reload() }
    }

    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier],
        requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        self.serviceIdentifiers = serviceIdentifiers
        passkeyParameters = requestParameters
        unlock { [weak self] _ in self?.reload() }
    }

    /// A suggestion in the password menu was chosen. The key needs Touch ID,
    /// so macOS has to show our interface first.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        extensionContext.cancelRequest(withError: Self.error(.userInteractionRequired))
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
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
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try Vault.load(reason: L.reason) }
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

    private func choose(_ row: Row) {
        switch row {
        case .header:
            break
        case let .login(login):
            complete(login: login)
        case let .passkey(_, passkey):
            guard let params = passkeyParameters else { return }
            complete(passkey: passkey, clientDataHash: params.clientDataHash)
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
        messageLabel.stringValue = message
        messageLabel.isHidden = false
        messageButton.title = button
        messageButton.isHidden = false
        messageButton.keyEquivalent = "\r"
        messageAction = action
        scrollView.isHidden = true
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
        let matchesQuery: (Login) -> Bool = { login in
            query.isEmpty || login.title.lowercased().contains(query) || login.username.lowercased().contains(query)
                || login.domains.contains { $0.contains(query) }
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
        let withPassword = cache.logins.filter { !$0.password.isEmpty && matchesQuery($0) }
        let suggested = withPassword.filter { !Set($0.domains).isDisjoint(with: wanted) }
        let others = withPassword.filter { Set($0.domains).isDisjoint(with: wanted) }
        if !suggested.isEmpty { rows += [Row.header(L.suggested)] + suggested.map(Row.login) }
        if !others.isEmpty { rows += [Row.header(L.all)] + others.map(Row.login) }
        self.rows = rows
        tableView.reloadData()

        searchField.isHidden = false
        scrollView.isHidden = rows.isEmpty
        messageLabel.isHidden = !rows.isEmpty
        messageLabel.stringValue = L.nothing
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

    func tableView(_: NSTableView, isGroupRow row: Int) -> Bool {
        rows.indices.contains(row) && !rows[row].selectable
    }

    func tableView(_: NSTableView, shouldSelectRow row: Int) -> Bool {
        rows.indices.contains(row) && rows[row].selectable
    }

    func tableView(_: NSTableView, heightOfRow row: Int) -> CGFloat {
        rows.indices.contains(row) && !rows[row].selectable ? 26 : 40
    }

    func tableView(_: NSTableView, viewFor _: NSTableColumn?, row: Int) -> NSView? {
        guard rows.indices.contains(row) else { return nil }
        switch rows[row] {
        case let .header(title):
            let label = NSTextField(labelWithString: title)
            label.font = .systemFont(ofSize: NSFont.smallSystemFontSize, weight: .semibold)
            label.textColor = .secondaryLabelColor
            return cell([label])
        case let .login(login):
            return item(symbol: "key.fill", title: login.title, subtitle: login.username)
        case let .passkey(login, passkey):
            return item(
                symbol: "person.badge.key.fill",
                title: passkey.userName.isEmpty ? login.username : passkey.userName,
                subtitle: "\(login.title) · \(passkey.rpId)"
            )
        }
    }

    private func item(symbol: String, title: String, subtitle: String) -> NSView {
        let image = NSImageView(image: NSImage(systemSymbolName: symbol, accessibilityDescription: nil) ?? NSImage())
        image.contentTintColor = .controlAccentColor
        image.setContentHuggingPriority(.required, for: .horizontal)
        let titleLabel = NSTextField(labelWithString: title)
        titleLabel.lineBreakMode = .byTruncatingTail
        let subtitleLabel = NSTextField(labelWithString: subtitle)
        subtitleLabel.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        subtitleLabel.textColor = .secondaryLabelColor
        subtitleLabel.lineBreakMode = .byTruncatingTail
        let texts = NSStackView(views: [titleLabel, subtitleLabel])
        texts.orientation = .vertical
        texts.alignment = .leading
        texts.spacing = 1
        return cell([image, texts])
    }

    /// A row: the views side by side, vertically centred.
    private func cell(_ views: [NSView]) -> NSView {
        let row = NSStackView(views: views)
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 10
        row.edgeInsets = NSEdgeInsets(top: 0, left: 4, bottom: 0, right: 4)
        let cell = NSTableCellView()
        row.translatesAutoresizingMaskIntoConstraints = false
        cell.addSubview(row)
        NSLayoutConstraint.activate([
            row.leadingAnchor.constraint(equalTo: cell.leadingAnchor),
            row.trailingAnchor.constraint(lessThanOrEqualTo: cell.trailingAnchor),
            row.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
        ])
        return cell
    }
}
