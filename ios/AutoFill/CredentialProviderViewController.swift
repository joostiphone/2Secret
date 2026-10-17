import AuthenticationServices
import UIKit

/// AutoFill for passwords, passkeys and verification codes (Settings →
/// General → AutoFill & Passwords → 2Secret). It fills from the cache the
/// 2Secret app keeps while unlocking with Face ID or Touch ID is on (see
/// Vault.swift); it cannot change the vault.
@objc(CredentialProviderViewController)
final class CredentialProviderViewController: ASCredentialProviderViewController,
    UITableViewDataSource, UITableViewDelegate, UISearchBarDelegate
{
    private enum Row {
        case login(Login)
        case passkey(Login, Passkey)
        case code(Login)
    }

    private let tableView = UITableView(frame: .zero, style: .insetGrouped)
    private let searchBar = UISearchBar()
    private let messageLabel = UILabel()
    private var cache: AutofillCache?
    private var serviceIdentifiers: [ASCredentialServiceIdentifier] = []
    private var passkeyParameters: ASPasskeyCredentialRequestParameters?
    /// The list is for a verification code field (iOS 18).
    private var oneTimeCodes = false
    private var sections: [(title: String, rows: [Row])] = []

    // MARK: - Layout

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemGroupedBackground

        let title = UILabel()
        title.text = "2Secret"
        title.font = .preferredFont(forTextStyle: .headline)
        let cancel = UIButton(type: .system)
        cancel.setTitle(L.cancel, for: .normal)
        cancel.addTarget(self, action: #selector(cancelTapped), for: .touchUpInside)
        let header = UIStackView(arrangedSubviews: [title, UIView(), cancel])
        header.axis = .horizontal
        header.isLayoutMarginsRelativeArrangement = true
        header.layoutMargins = UIEdgeInsets(top: 12, left: 20, bottom: 4, right: 20)

        searchBar.placeholder = L.search
        searchBar.searchBarStyle = .minimal
        searchBar.autocapitalizationType = .none
        searchBar.delegate = self
        searchBar.isHidden = true

        messageLabel.numberOfLines = 0
        messageLabel.textAlignment = .center
        messageLabel.textColor = .secondaryLabel
        messageLabel.font = .preferredFont(forTextStyle: .body)
        messageLabel.text = L.unlocking

        tableView.dataSource = self
        tableView.delegate = self
        tableView.isHidden = true

        let stack = UIStackView(arrangedSubviews: [header, searchBar, messageLabel, tableView])
        stack.axis = .vertical
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            stack.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor),
            stack.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            messageLabel.heightAnchor.constraint(greaterThanOrEqualToConstant: 120),
        ])
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

    /// A verification code field: the logins with a one-time password.
    @available(iOS 18.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        self.serviceIdentifiers = serviceIdentifiers
        oneTimeCodes = true
        unlock { [weak self] _ in self?.reload() }
    }

    /// A suggestion above the keyboard was chosen. The key needs Face ID, so
    /// iOS has to show our interface first.
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

    // MARK: - The list

    private var messageAction: (() -> Void)?

    private func show(message: String, button: String, action: @escaping () -> Void) {
        loadViewIfNeeded()
        messageLabel.text = message
        messageLabel.isHidden = false
        tableView.isHidden = true
        searchBar.isHidden = true
        messageAction = action
        let done = UIButton(type: .system)
        done.setTitle(button, for: .normal)
        done.addTarget(self, action: #selector(messageButtonTapped), for: .touchUpInside)
        if let stack = messageLabel.superview as? UIStackView, !stack.arrangedSubviews.contains(where: { $0.tag == 42 }) {
            done.tag = 42
            stack.insertArrangedSubview(done, at: stack.arrangedSubviews.firstIndex(of: messageLabel)! + 1)
        }
    }

    @objc private func messageButtonTapped() {
        messageAction?()
    }

    private func reload() {
        guard let cache else { return }
        loadViewIfNeeded()
        let query = searchBar.text?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
        let wanted = Vault.candidates(serviceIdentifiers)
        let matchesQuery: (Login) -> Bool = { login in
            query.isEmpty || login.title.lowercased().contains(query) || login.username.lowercased().contains(query)
                || login.domains.contains { $0.contains(query) }
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
        let suggested = listed.filter { !Set($0.domains).isDisjoint(with: wanted) }
        let others = listed.filter { Set($0.domains).isDisjoint(with: wanted) }
        if !suggested.isEmpty { sections.append((L.suggested, suggested.map(row))) }
        if !others.isEmpty { sections.append((L.all, others.map(row))) }
        self.sections = sections.map { (title: $0.0, rows: $0.1) }

        searchBar.isHidden = false
        tableView.isHidden = sections.isEmpty
        messageLabel.isHidden = !sections.isEmpty
        messageLabel.text = oneTimeCodes && query.isEmpty ? L.noCodes : L.nothing
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

    func tableView(_: UITableView, numberOfRowsInSection section: Int) -> Int {
        sections[section].rows.count
    }

    func tableView(_: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        var content = cell.defaultContentConfiguration()
        switch sections[indexPath.section].rows[indexPath.row] {
        case let .login(login):
            content.text = login.title
            content.secondaryText = login.username
            content.image = UIImage(systemName: "key.fill")
        case let .passkey(login, passkey):
            content.text = passkey.userName.isEmpty ? login.username : passkey.userName
            content.secondaryText = "\(login.title) · \(passkey.rpId)"
            content.image = UIImage(systemName: "person.badge.key.fill")
        case let .code(login):
            content.text = login.title
            content.secondaryText = login.username
            content.image = UIImage(systemName: "clock.fill")
        }
        content.imageProperties.tintColor = .systemBlue
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
