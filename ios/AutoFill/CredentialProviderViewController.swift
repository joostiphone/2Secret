import AuthenticationServices
import UIKit

/// AutoFill for passwords, passkeys and verification codes (Settings →
/// General → AutoFill & Passwords → 2Secret). It fills from the cache the
/// 2Secret app keeps while unlocking with Face ID or Touch ID is on (see
/// Vault.swift); it cannot change the vault. The panel looks like the app:
/// its colours (`Brand`), its logo, its theme, and the websites' icons.
@objc(CredentialProviderViewController)
final class CredentialProviderViewController: ASCredentialProviderViewController,
    UITableViewDataSource, UITableViewDelegate, UISearchBarDelegate
{
    private enum Row {
        case login(Login)
        case passkey(Login, Passkey)
        case code(Login)
    }

    private let hostLabel = UILabel()
    private let tableView = UITableView(frame: .zero, style: .insetGrouped)
    private let searchBar = UISearchBar()
    private let stateStack = UIStackView()
    private let bigLogo = UIImageView(image: Brand.logo)
    private let spinner = UIActivityIndicatorView(style: .medium)
    private let messageLabel = UILabel()
    private let messageHost = UILabel()
    private let messageButton = UIButton(type: .system)
    private var cache: AutofillCache?
    private var serviceIdentifiers: [ASCredentialServiceIdentifier] = []
    private var passkeyParameters: ASPasskeyCredentialRequestParameters?
    /// The list is for a verification code field (iOS 18).
    private var oneTimeCodes = false
    private var sections: [(title: String, rows: [Row])] = []
    private var messageAction: (() -> Void)?

    /// The website the request is for, as shown in the header and the Face
    /// ID dialog (`www.` left out).
    private var host: String? {
        let hosts = Vault.hosts(serviceIdentifiers).map { h -> String in
            h.hasPrefix("www.") ? String(h.dropFirst(4)) : h
        }
        return hosts.sorted().first
    }

    // MARK: - Layout

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = Brand.bg
        // The app's theme; "system" follows iOS.
        switch Vault.theme() {
        case "dark": overrideUserInterfaceStyle = .dark
        case "light": overrideUserInterfaceStyle = .light
        default: break
        }

        // Header: logo, name, the website, Cancel.
        let logo = UIImageView(image: Brand.logo)
        logo.contentMode = .scaleAspectFit
        logo.layer.cornerRadius = 7
        logo.clipsToBounds = true
        logo.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            logo.widthAnchor.constraint(equalToConstant: 30),
            logo.heightAnchor.constraint(equalToConstant: 30),
        ])
        let title = UILabel()
        title.text = "2Secret"
        title.font = .systemFont(ofSize: 17, weight: .semibold)
        title.textColor = Brand.text
        hostLabel.font = .systemFont(ofSize: 13)
        hostLabel.textColor = Brand.muted
        hostLabel.lineBreakMode = .byTruncatingMiddle
        hostLabel.isHidden = true
        let names = UIStackView(arrangedSubviews: [title, hostLabel])
        names.axis = .vertical
        names.spacing = 1
        let cancel = UIButton(type: .system)
        cancel.setTitle(L.cancel, for: .normal)
        cancel.tintColor = Brand.accent
        cancel.titleLabel?.font = .systemFont(ofSize: 17)
        cancel.addTarget(self, action: #selector(cancelTapped), for: .touchUpInside)
        cancel.setContentHuggingPriority(.required, for: .horizontal)
        let header = UIStackView(arrangedSubviews: [logo, names, UIView(), cancel])
        header.axis = .horizontal
        header.alignment = .center
        header.spacing = 10
        header.isLayoutMarginsRelativeArrangement = true
        header.layoutMargins = UIEdgeInsets(top: 12, left: 20, bottom: 4, right: 20)

        searchBar.placeholder = L.search
        searchBar.searchBarStyle = .minimal
        searchBar.autocapitalizationType = .none
        searchBar.tintColor = Brand.accent
        searchBar.delegate = self
        searchBar.isHidden = true

        tableView.dataSource = self
        tableView.delegate = self
        tableView.backgroundColor = .clear
        tableView.separatorColor = Brand.border
        tableView.isHidden = true

        // Unlocking, and messages: logo, spinner, text, website, a button.
        bigLogo.contentMode = .scaleAspectFit
        bigLogo.layer.cornerRadius = 16
        bigLogo.clipsToBounds = true
        bigLogo.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            bigLogo.widthAnchor.constraint(equalToConstant: 64),
            bigLogo.heightAnchor.constraint(equalToConstant: 64),
        ])
        spinner.color = Brand.muted
        spinner.hidesWhenStopped = true
        spinner.startAnimating()
        messageLabel.numberOfLines = 0
        messageLabel.textAlignment = .center
        messageLabel.textColor = Brand.text
        messageLabel.font = .preferredFont(forTextStyle: .body)
        messageLabel.text = L.unlocking
        messageHost.textAlignment = .center
        messageHost.textColor = Brand.muted
        messageHost.font = .preferredFont(forTextStyle: .subheadline)
        messageHost.isHidden = true
        messageButton.tintColor = Brand.accent
        messageButton.titleLabel?.font = .systemFont(ofSize: 17, weight: .semibold)
        messageButton.addTarget(self, action: #selector(messageButtonTapped), for: .touchUpInside)
        messageButton.isHidden = true
        for subview in [bigLogo, spinner, messageLabel, messageHost, messageButton] {
            stateStack.addArrangedSubview(subview)
        }
        stateStack.axis = .vertical
        stateStack.alignment = .center
        stateStack.spacing = 12
        stateStack.setCustomSpacing(20, after: bigLogo)
        stateStack.isLayoutMarginsRelativeArrangement = true
        stateStack.layoutMargins = UIEdgeInsets(top: 48, left: 32, bottom: 24, right: 32)

        let stack = UIStackView(arrangedSubviews: [header, searchBar, stateStack, tableView])
        stack.axis = .vertical
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            stack.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor),
            stack.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }

    /// Show the website in the header and under the unlocking message.
    private func showHost() {
        loadViewIfNeeded()
        let site = host ?? ""
        hostLabel.text = site
        hostLabel.isHidden = site.isEmpty
        messageHost.text = L.forSite(site)
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
    @available(iOS 18.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        self.serviceIdentifiers = serviceIdentifiers
        oneTimeCodes = true
        showHost()
        unlock { [weak self] _ in self?.reload() }
    }

    /// A suggestion above the keyboard was chosen. The key needs Face ID, so
    /// iOS has to show our interface first.
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
            } else if #available(iOS 18.0, *),
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
        guard #available(iOS 18.0, *), let code = login.totp?.code() else {
            extensionContext.cancelRequest(withError: Self.error(.failed))
            return
        }
        extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code), completionHandler: nil)
    }

    @objc private func cancelTapped() {
        extensionContext.cancelRequest(withError: Self.error(.userCanceled))
    }

    private static func error(_ code: ASExtensionError.Code) -> NSError {
        NSError(domain: ASExtensionErrorDomain, code: code.rawValue)
    }

    // MARK: - Messages

    private func show(message: String, button: String, action: @escaping () -> Void) {
        loadViewIfNeeded()
        spinner.stopAnimating()
        bigLogo.isHidden = false
        messageLabel.text = message
        messageLabel.textColor = Brand.muted
        messageHost.isHidden = true
        messageButton.setTitle(button, for: .normal)
        messageButton.isHidden = false
        messageAction = action
        stateStack.isHidden = false
        tableView.isHidden = true
        searchBar.isHidden = true
    }

    @objc private func messageButtonTapped() {
        messageAction?()
    }

    // MARK: - The list

    private func reload() {
        guard let cache else { return }
        loadViewIfNeeded()
        let query = searchBar.text?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
        let wanted = Vault.candidates(serviceIdentifiers)
        let hosts = Vault.hosts(serviceIdentifiers)
        let matchesQuery: (Login) -> Bool = { login in
            query.isEmpty || login.title.lowercased().contains(query) || login.username.lowercased().contains(query)
                || (login.domains + (login.exactHosts ?? [])).contains { $0.contains(query) }
        }
        var sections: [(String, [Row])] = []

        if let params = passkeyParameters {
            let allowed = Set(params.allowedCredentials)
            var rows: [Row] = []
            for login in cache.logins {
                for passkey in login.passkeys where passkey.rpId == params.relyingPartyIdentifier {
                    if allowed.isEmpty || Vault.data(base64url: passkey.credentialId).map(allowed.contains) == true {
                        rows.append(.passkey(login, passkey))
                    }
                }
            }
            if !rows.isEmpty { sections.append((L.passkeys, rows)) }
        }
        // Logins with a password, or with a one-time password for a code field.
        let listed = cache.logins.filter { (oneTimeCodes ? $0.totp != nil : !$0.password.isEmpty) && matchesQuery($0) }
        let row: (Login) -> Row = oneTimeCodes ? Row.code : Row.login
        let suggested = listed.filter { $0.isFor(candidates: wanted, hosts: hosts) }
        let others = listed.filter { !$0.isFor(candidates: wanted, hosts: hosts) }
        if !suggested.isEmpty { sections.append((L.suggested, suggested.map(row))) }
        if !others.isEmpty { sections.append((L.all, others.map(row))) }
        self.sections = sections.map { (title: $0.0, rows: $0.1) }

        spinner.stopAnimating()
        searchBar.isHidden = false
        tableView.isHidden = sections.isEmpty
        stateStack.isHidden = !sections.isEmpty
        bigLogo.isHidden = true
        messageLabel.text = oneTimeCodes && query.isEmpty ? L.noCodes : L.nothing
        messageLabel.textColor = Brand.muted
        messageHost.isHidden = true
        messageButton.isHidden = true
        tableView.reloadData()
    }

    func searchBar(_: UISearchBar, textDidChange _: String) {
        reload()
    }

    func numberOfSections(in _: UITableView) -> Int {
        sections.count
    }

    func tableView(_: UITableView, titleForHeaderInSection section: Int) -> String? {
        sections[section].title
    }

    func tableView(_: UITableView, willDisplayHeaderView view: UIView, forSection _: Int) {
        if let header = view as? UITableViewHeaderFooterView {
            header.textLabel?.textColor = Brand.muted
            header.textLabel?.font = .systemFont(ofSize: 13, weight: .semibold)
        }
    }

    func tableView(_: UITableView, numberOfRowsInSection section: Int) -> Int {
        sections[section].rows.count
    }

    func tableView(_: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        cell.backgroundColor = Brand.panel
        let selected = UIView()
        selected.backgroundColor = Brand.selected
        cell.selectedBackgroundView = selected
        var content = cell.defaultContentConfiguration()
        let login: Login
        let symbol: String
        switch sections[indexPath.section].rows[indexPath.row] {
        case let .login(l):
            login = l
            symbol = "key.fill"
            content.text = l.title
            content.secondaryText = l.username
        case let .passkey(l, passkey):
            login = l
            symbol = "person.badge.key.fill"
            content.text = passkey.userName.isEmpty ? l.username : passkey.userName
            content.secondaryText = "\(l.title) · \(passkey.rpId)"
        case let .code(l):
            login = l
            symbol = "clock.fill"
            content.text = l.title
            content.secondaryText = l.username
        }
        content.textProperties.color = Brand.text
        content.textProperties.font = .systemFont(ofSize: 16, weight: .medium)
        content.secondaryTextProperties.color = Brand.muted
        content.secondaryTextProperties.font = .systemFont(ofSize: 13)
        content.imageProperties.maximumSize = CGSize(width: 30, height: 30)
        content.imageProperties.reservedLayoutSize = CGSize(width: 30, height: 30)
        if let data = Vault.imageData(dataURL: login.icon), let image = UIImage(data: data) {
            content.image = image
            content.imageProperties.cornerRadius = 7
        } else {
            content.image = UIImage(systemName: symbol)
            content.imageProperties.tintColor = Brand.accent
        }
        cell.contentConfiguration = content
        return cell
    }

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        switch sections[indexPath.section].rows[indexPath.row] {
        case let .login(login):
            complete(login: login)
        case let .passkey(_, passkey):
            guard let params = passkeyParameters else { return }
            complete(passkey: passkey, clientDataHash: params.clientDataHash)
        case let .code(login):
            complete(code: login)
        }
    }
}
